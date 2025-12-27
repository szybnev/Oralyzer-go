package oralyzer

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

// NewPayloadManager creates a payload manager with custom or default payloads.
func NewPayloadManager(customPayloads []string) *PayloadManager {
	payloads := customPayloads
	if len(payloads) == 0 {
		payloads = DefaultPayloads
	}

	return &PayloadManager{basePayloads: payloads}
}

// LoadPayloadsFromFile loads payloads from an external file.
func LoadPayloadsFromFile(path string) ([]string, error) {
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

// GetPayloads returns base payloads.
func (pm *PayloadManager) GetPayloads() []string {
	return pm.basePayloads
}

// GenerateRegexBypassPayloads creates payloads to bypass faulty regex.
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
		regexPayloads = append(regexPayloads, payload+"."+domain)
		regexPayloads = append(regexPayloads, payload+"/"+domain)
	}

	return regexPayloads
}

// GetAllPayloads returns base payloads plus regex bypass variants.
func (pm *PayloadManager) GetAllPayloads(targetURL string) []string {
	all := make([]string, len(pm.basePayloads))
	copy(all, pm.basePayloads)
	return append(all, pm.GenerateRegexBypassPayloads(targetURL)...)
}

// GenerateTestCases generates all test cases for a URL.
func (pm *PayloadManager) GenerateTestCases(targetURL string) []scanJob {
	targetURL = EnsureScheme(targetURL)
	allPayloads := pm.GetAllPayloads(targetURL)

	var jobs []scanJob

	if strings.Contains(targetURL, "=") {
		jobs = pm.generateParameterizedJobs(targetURL, allPayloads)
	} else {
		jobs = pm.generatePathJobs(targetURL, allPayloads)
	}

	return jobs
}

// generateParameterizedJobs creates jobs for URLs with query parameters.
func (pm *PayloadManager) generateParameterizedJobs(targetURL string, payloads []string) []scanJob {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	query := parsedURL.Query()
	if len(query) == 0 {
		return pm.generatePathJobs(targetURL, payloads)
	}

	baseURL := *parsedURL
	baseURL.RawQuery = ""
	baseURLStr := baseURL.String()

	var jobs []scanJob

	for key := range query {
		originalValue := query.Get(key)

		for _, payload := range payloads {
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
				Mode:    ModeOpenRedirect,
			})
		}

		query.Set(key, originalValue)
	}

	return jobs
}

// generatePathJobs creates jobs for URLs without query parameters.
func (pm *PayloadManager) generatePathJobs(targetURL string, payloads []string) []scanJob {
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}

	var jobs []scanJob
	for _, payload := range payloads {
		jobs = append(jobs, scanJob{
			URL:     targetURL + payload,
			BaseURL: targetURL,
			Payload: payload,
			Params:  nil,
			Mode:    ModeOpenRedirect,
		})
	}

	return jobs
}
