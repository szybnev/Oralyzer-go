package main

import (
	"bufio"
	_ "embed"
	"net/url"
	"os"
	"strings"
)

//go:embed payloads.txt
var embeddedPayloads string

// NewPayloadManager creates a payload manager
func NewPayloadManager(customFile string) (*PayloadManager, error) {
	var payloads []string
	var err error

	if customFile != "" {
		payloads, err = loadPayloadsFromFile(customFile)
	} else {
		payloads = loadEmbeddedPayloads()
	}

	if err != nil {
		return nil, err
	}

	return &PayloadManager{basePayloads: payloads}, nil
}

// loadEmbeddedPayloads loads payloads from embedded file
func loadEmbeddedPayloads() []string {
	return parsePayloadLines(embeddedPayloads)
}

// loadPayloadsFromFile loads payloads from external file
func loadPayloadsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	return payloads, scanner.Err()
}

// parsePayloadLines splits payload content into lines
func parsePayloadLines(content string) []string {
	var payloads []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}
	return payloads
}

// GetPayloads returns base payloads
func (pm *PayloadManager) GetPayloads() []string {
	return pm.basePayloads
}

// GenerateRegexBypassPayloads creates payloads to bypass faulty regex
// Maps to Python's generator() function in core/others.py
func (pm *PayloadManager) GenerateRegexBypassPayloads(targetURL string) []string {
	parsedURL, err := url.Parse(EnsureScheme(targetURL))
	if err != nil {
		return nil
	}

	domain := parsedURL.Host
	if domain == "" {
		return nil
	}

	var regexPayloads []string
	for _, payload := range pm.basePayloads {
		// {payload}.{domain} pattern - subdomain style
		regexPayloads = append(regexPayloads, payload+"."+domain)
		// {payload}/{domain} pattern - path style
		regexPayloads = append(regexPayloads, payload+"/"+domain)
	}

	return regexPayloads
}

// GetAllPayloads returns base payloads plus regex bypass variants
func (pm *PayloadManager) GetAllPayloads(targetURL string) []string {
	all := make([]string, len(pm.basePayloads))
	copy(all, pm.basePayloads)
	return append(all, pm.GenerateRegexBypassPayloads(targetURL)...)
}

// GenerateTestCases generates all test cases for a URL
// Maps to Python's multitest() function in core/others.py
func (pm *PayloadManager) GenerateTestCases(targetURL string) []ScanJob {
	targetURL = EnsureScheme(targetURL)
	allPayloads := pm.GetAllPayloads(targetURL)

	var jobs []ScanJob

	// Check if URL has query parameters
	if strings.Contains(targetURL, "=") {
		// Handle parameterized URLs
		jobs = pm.generateParameterizedJobs(targetURL, allPayloads)
	} else {
		// Handle URLs without parameters - append payloads to path
		jobs = pm.generatePathJobs(targetURL, allPayloads)
	}

	return jobs
}

// generateParameterizedJobs creates jobs for URLs with query parameters
func (pm *PayloadManager) generateParameterizedJobs(targetURL string, payloads []string) []ScanJob {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	// Get query parameters
	query := parsedURL.Query()
	if len(query) == 0 {
		return pm.generatePathJobs(targetURL, payloads)
	}

	// Build base URL without query string
	baseURL := *parsedURL
	baseURL.RawQuery = ""
	baseURLStr := baseURL.String()

	var jobs []ScanJob

	// For each parameter, inject each payload
	for key := range query {
		originalValue := query.Get(key)

		for _, payload := range payloads {
			// Create a copy of query params
			params := make(map[string]string)
			for k := range query {
				if k == key {
					params[k] = payload
				} else {
					params[k] = query.Get(k)
				}
			}

			jobs = append(jobs, ScanJob{
				URL:     baseURLStr,
				BaseURL: targetURL,
				Payload: payload,
				Params:  params,
				Mode:    ModeOpenRedirect,
			})
		}

		// Restore original value for next parameter
		query.Set(key, originalValue)
	}

	return jobs
}

// generatePathJobs creates jobs for URLs without query parameters
func (pm *PayloadManager) generatePathJobs(targetURL string, payloads []string) []ScanJob {
	// Ensure URL ends with /
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}

	var jobs []ScanJob
	for _, payload := range payloads {
		jobs = append(jobs, ScanJob{
			URL:     targetURL + payload,
			BaseURL: targetURL,
			Payload: payload,
			Params:  nil,
			Mode:    ModeOpenRedirect,
		})
	}

	return jobs
}
