package main

import (
	"net/url"
	"strings"
	"time"
)

// NewCRLFScanner creates a CRLF scanner with hardcoded payloads
func NewCRLFScanner(client *HTTPClient) *CRLFScanner {
	return &CRLFScanner{
		payloads:   CRLFPayloads,
		httpClient: client,
	}
}

// GenerateJobs creates test cases for CRLF scanning
func (c *CRLFScanner) GenerateJobs(targetURL string) []ScanJob {
	targetURL = EnsureScheme(targetURL)

	var jobs []ScanJob

	// Check if URL has query parameters
	if strings.Contains(targetURL, "=") {
		jobs = c.generateParameterizedJobs(targetURL)
	} else {
		jobs = c.generatePathJobs(targetURL)
	}

	return jobs
}

// generateParameterizedJobs creates jobs for URLs with query parameters
func (c *CRLFScanner) generateParameterizedJobs(targetURL string) []ScanJob {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return c.generatePathJobs(targetURL)
	}

	query := parsedURL.Query()
	if len(query) == 0 {
		return c.generatePathJobs(targetURL)
	}

	// Build base URL without query string
	baseURL := *parsedURL
	baseURL.RawQuery = ""
	baseURLStr := baseURL.String()

	var jobs []ScanJob

	// For each parameter, inject each CRLF payload
	for key := range query {
		originalValue := query.Get(key)

		for _, payload := range c.payloads {
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
				Mode:    ModeCRLF,
			})
		}

		query.Set(key, originalValue)
	}

	return jobs
}

// generatePathJobs creates jobs for URLs without query parameters
func (c *CRLFScanner) generatePathJobs(targetURL string) []ScanJob {
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}

	var jobs []ScanJob
	for _, payload := range c.payloads {
		jobs = append(jobs, ScanJob{
			URL:     targetURL + payload,
			BaseURL: targetURL,
			Payload: payload,
			Params:  nil,
			Mode:    ModeCRLF,
		})
	}

	return jobs
}

// TestPayload tests a single CRLF payload
func (c *CRLFScanner) TestPayload(job ScanJob) ScanResult {
	resp, _, err := c.httpClient.Get(job.URL, job.Params)
	if err != nil {
		return ScanResult{
			URL:         job.URL,
			OriginalURL: job.BaseURL,
			Payload:     job.Payload,
			Error:       err.Error(),
			Timestamp:   time.Now(),
		}
	}

	// Convert http.Response to our wrapper
	httpResp := &httpResponse{
		StatusCode: resp.StatusCode,
		Header:     httpHeader(resp.Header),
	}

	return c.checkInjection(httpResp, job)
}

// checkInjection examines response headers for CRLF indicators
// Maps to Python's basicChecks() function in crlf.py
func (c *CRLFScanner) checkInjection(resp *httpResponse, job ScanJob) ScanResult {
	result := ScanResult{
		URL:         job.URL,
		OriginalURL: job.BaseURL,
		Payload:     job.Payload,
		StatusCode:  resp.StatusCode,
		Timestamp:   time.Now(),
	}

	// Check for injected Location header (to google.com variants)
	location := resp.Header.Get("Location")
	if isGoogleRedirect(location) {
		result.Vulnerable = true
		result.VulnType = VulnCRLFInjection
		result.RedirectURL = location
		return result
	}

	// Check for injected Set-Cookie header
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		if strings.Contains(cookie, "name=ch33ms") {
			result.Vulnerable = true
			result.VulnType = VulnCRLFInjection
			return result
		}
	}

	// Check for error codes
	if isErrorCode(resp.StatusCode) {
		result.Error = "HTTP error"
	}

	return result
}

// httpResponse wraps response data for CRLF checking
type httpResponse struct {
	StatusCode int
	Header     httpHeader
}

// httpHeader wraps http.Header for convenience
type httpHeader map[string][]string

func (h httpHeader) Get(key string) string {
	if values, ok := h[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func (h httpHeader) Values(key string) []string {
	return h[key]
}

// isGoogleRedirect checks if Location header points to google.com
func isGoogleRedirect(location string) bool {
	for _, g := range GoogleVariants {
		if location == g {
			return true
		}
	}
	return false
}

// Scan tests a URL for CRLF injection (convenience method)
func (c *CRLFScanner) Scan(targetURL string) []ScanResult {
	var results []ScanResult

	jobs := c.GenerateJobs(targetURL)
	for _, job := range jobs {
		result := c.TestPayload(job)
		results = append(results, result)

		if result.Vulnerable {
			break // Stop on first vulnerability (like Python)
		}
	}

	return results
}
