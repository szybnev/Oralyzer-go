package oralyzer

import (
	"context"
	"fmt"
	"sync"
)

const (
	jobBufferSize    = 100
	resultBufferSize = 50
)

// NewScanner creates a new scanner instance.
func NewScanner(config *Config) (*Scanner, error) {
	if config == nil {
		config = &Config{}
	}

	// Set defaults
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * 1e9 // 10 seconds
	}

	// Create HTTP client
	httpClient, err := newHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Load payloads
	payloads := NewPayloadManager(config.Payloads)

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
		jobs:        make(chan scanJob, jobBufferSize),
		results:     make(chan Result, resultBufferSize),
	}, nil
}

// Scan performs a scan and returns all results.
func (s *Scanner) Scan(ctx context.Context) ([]Result, error) {
	var allResults []Result
	var mu sync.Mutex

	err := s.ScanWithCallback(ctx, func(result Result) {
		mu.Lock()
		allResults = append(allResults, result)
		mu.Unlock()
	})

	return allResults, err
}

// ScanWithCallback performs a scan and calls the handler for each result.
func (s *Scanner) ScanWithCallback(ctx context.Context, handler ResultHandler) error {
	// Start result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		s.collectResults(ctx, handler)
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

// ScanURL scans a single URL and returns results.
func (s *Scanner) ScanURL(ctx context.Context, targetURL string) ([]Result, error) {
	s.config.URLs = []string{targetURL}
	return s.Scan(ctx)
}

// ScanURLs scans multiple URLs and returns results.
func (s *Scanner) ScanURLs(ctx context.Context, urls []string) ([]Result, error) {
	s.config.URLs = urls
	return s.Scan(ctx)
}

// startWorkers launches worker goroutines.
func (s *Scanner) startWorkers(ctx context.Context, numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
}

// worker processes jobs from the job channel.
func (s *Scanner) worker(ctx context.Context) {
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

// processJob executes a single scan job.
func (s *Scanner) processJob(ctx context.Context, job scanJob) Result {
	switch job.Mode {
	case ModeCRLF:
		return s.processCRLFJob(job)
	default:
		return s.processRedirectJob(job)
	}
}

// processRedirectJob handles open redirect scanning.
func (s *Scanner) processRedirectJob(job scanJob) Result {
	resp, body, err := s.httpClient.Get(job.URL, job.Params)
	if err != nil {
		return Result{
			URL:         job.URL,
			OriginalURL: job.BaseURL,
			Payload:     job.Payload,
			Error:       err.Error(),
		}
	}

	finalURL := job.URL
	if len(job.Params) > 0 {
		finalURL, _ = buildRequestURL(job.URL, job.Params)
	}

	result := s.detector.Analyze(resp, body, finalURL)
	result.OriginalURL = job.BaseURL
	result.Payload = job.Payload

	return result
}

// processCRLFJob handles CRLF injection scanning.
func (s *Scanner) processCRLFJob(job scanJob) Result {
	return s.crlfScanner.TestPayload(job)
}

// dispatchJobs generates and sends jobs to workers.
func (s *Scanner) dispatchJobs(ctx context.Context) {
	defer close(s.jobs)

	for _, targetURL := range s.config.URLs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var jobs []scanJob

		switch s.config.Mode {
		case ModeCRLF:
			jobs = s.crlfScanner.GenerateJobs(targetURL)
		default:
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

// collectResults processes results from workers.
func (s *Scanner) collectResults(ctx context.Context, handler ResultHandler) {
	for {
		select {
		case <-ctx.Done():
			for result := range s.results {
				if handler != nil {
					handler(result)
				}
			}
			return
		case result, ok := <-s.results:
			if !ok {
				return
			}
			if handler != nil {
				handler(result)
			}
		}
	}
}
