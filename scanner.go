package main

import (
	"context"
	"fmt"
	"sync"
)

const (
	jobBufferSize    = 100
	resultBufferSize = 50
)

// NewScanner creates a new scanner instance
func NewScanner(config *Config) (*Scanner, error) {
	// Create HTTP client
	httpClient, err := NewHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Load payloads
	payloads, err := NewPayloadManager(config.PayloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load payloads: %w", err)
	}

	// Create output manager
	output, err := NewOutputManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create output manager: %w", err)
	}

	// Create detector
	detector := NewDetector(payloads.GetPayloads())

	// Create CRLF scanner
	crlfScanner := NewCRLFScanner(httpClient)

	return &Scanner{
		config:      config,
		httpClient:  httpClient,
		payloads:    payloads,
		detector:    detector,
		crlfScanner: crlfScanner,
		jobs:        make(chan ScanJob, jobBufferSize),
		results:     make(chan ScanResult, resultBufferSize),
		output:      output,
	}, nil
}

// Start begins the scanning process
func (s *Scanner) Start(ctx context.Context) error {
	// Start result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		s.collectResults(ctx)
	}()

	// Start workers
	s.startWorkers(ctx, s.config.Concurrency)

	// Dispatch jobs
	s.dispatchJobs(ctx)

	// Wait for workers to finish
	s.wg.Wait()
	close(s.results)

	// Wait for collector to finish
	collectorWg.Wait()

	return nil
}

// startWorkers launches worker goroutines
func (s *Scanner) startWorkers(ctx context.Context, numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, i)
	}
}

// worker processes jobs from the job channel
func (s *Scanner) worker(ctx context.Context, id int) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-s.jobs:
			if !ok {
				return
			}
			result := s.processJob(ctx, job)
			select {
			case s.results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processJob executes a single scan job
func (s *Scanner) processJob(ctx context.Context, job ScanJob) ScanResult {
	switch job.Mode {
	case ModeCRLF:
		return s.processCRLFJob(job)
	default:
		return s.processRedirectJob(job)
	}
}

// processRedirectJob handles open redirect scanning
func (s *Scanner) processRedirectJob(job ScanJob) ScanResult {
	// Execute HTTP request
	resp, body, err := s.httpClient.Get(job.URL, job.Params)
	if err != nil {
		return ScanResult{
			URL:         job.URL,
			OriginalURL: job.BaseURL,
			Payload:     job.Payload,
			Error:       err.Error(),
		}
	}

	// Get final URL
	finalURL := job.URL
	if len(job.Params) > 0 {
		finalURL, _ = buildRequestURL(job.URL, job.Params)
	}

	// Analyze response
	result := s.detector.Analyze(resp, body, finalURL)
	result.OriginalURL = job.BaseURL
	result.Payload = job.Payload

	return result
}

// processCRLFJob handles CRLF injection scanning
func (s *Scanner) processCRLFJob(job ScanJob) ScanResult {
	return s.crlfScanner.TestPayload(job)
}

// dispatchJobs generates and sends jobs to workers
func (s *Scanner) dispatchJobs(ctx context.Context) {
	defer close(s.jobs)

	for _, targetURL := range s.config.URLs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		PrintInfo("Target: %s", targetURL)

		var jobs []ScanJob

		switch s.config.ScanMode {
		case ModeCRLF:
			PrintInfo("Scanning for CRLF injection")
			jobs = s.crlfScanner.GenerateJobs(targetURL)
		default:
			PrintInfo("Infusing payloads")
			jobs = s.payloads.GenerateTestCases(targetURL)
		}

		for _, job := range jobs {
			select {
			case <-ctx.Done():
				return
			case s.jobs <- job:
			}
		}
	}
}

// collectResults processes results from workers
func (s *Scanner) collectResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Drain remaining results
			for result := range s.results {
				s.output.Write(result)
			}
			return
		case result, ok := <-s.results:
			if !ok {
				return
			}
			s.output.Write(result)
		}
	}
}

// Stop gracefully shuts down the scanner
func (s *Scanner) Stop() {
	s.output.Flush()
}
