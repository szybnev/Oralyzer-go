package oralyzer

import (
	"net/url"
	"strings"
	"time"
)

// NewCRLFScanner creates a CRLF scanner with hardcoded payloads.
func NewCRLFScanner(client *httpClient) *CRLFScanner {
	return &CRLFScanner{
		payloads:   CRLFPayloads,
		httpClient: client,
	}
}

// GenerateJobs creates test cases for CRLF scanning.
func (c *CRLFScanner) GenerateJobs(targetURL string) []scanJob {
	targetURL = EnsureScheme(targetURL)

	var jobs []scanJob

	if strings.Contains(targetURL, "=") {
		jobs = c.generateParameterizedJobs(targetURL)
	} else {
		jobs = c.generatePathJobs(targetURL)
	}

	return jobs
}

// generateParameterizedJobs creates jobs for URLs with query parameters.
func (c *CRLFScanner) generateParameterizedJobs(targetURL string) []scanJob {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return c.generatePathJobs(targetURL)
	}

	query := parsedURL.Query()
	if len(query) == 0 {
		return c.generatePathJobs(targetURL)
	}

	baseURL := *parsedURL
	baseURL.RawQuery = ""
	baseURLStr := baseURL.String()

	var jobs []scanJob

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

			jobs = append(jobs, scanJob{
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

// generatePathJobs creates jobs for URLs without query parameters.
func (c *CRLFScanner) generatePathJobs(targetURL string) []scanJob {
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}

	var jobs []scanJob
	for _, payload := range c.payloads {
		jobs = append(jobs, scanJob{
			URL:     targetURL + payload,
			BaseURL: targetURL,
			Payload: payload,
			Params:  nil,
			Mode:    ModeCRLF,
		})
	}

	return jobs
}

// TestPayload tests a single CRLF payload.
func (c *CRLFScanner) TestPayload(job scanJob) Result {
	resp, _, err := c.httpClient.Get(job.URL, job.Params)
	if err != nil {
		return Result{
			URL:         job.URL,
			OriginalURL: job.BaseURL,
			Payload:     job.Payload,
			Error:       err.Error(),
			Timestamp:   time.Now(),
		}
	}

	result := Result{
		URL:         job.URL,
		OriginalURL: job.BaseURL,
		Payload:     job.Payload,
		StatusCode:  resp.StatusCode,
		Timestamp:   time.Now(),
	}

	// Check for injected Location header
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

	if isErrorCode(resp.StatusCode) {
		result.Error = "HTTP error"
	}

	return result
}

// Scan tests a URL for CRLF injection.
func (c *CRLFScanner) Scan(targetURL string) []Result {
	var results []Result

	jobs := c.GenerateJobs(targetURL)
	for _, job := range jobs {
		result := c.TestPayload(job)
		results = append(results, result)

		if result.Vulnerable {
			break
		}
	}

	return results
}

// isGoogleRedirect checks if Location header points to google.com.
func isGoogleRedirect(location string) bool {
	for _, g := range GoogleVariants {
		if location == g {
			return true
		}
	}
	return false
}
