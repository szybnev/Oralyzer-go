package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// NewWaybackFetcher creates a new Wayback fetcher
func NewWaybackFetcher(client *HTTPClient) *WaybackFetcher {
	return &WaybackFetcher{
		httpClient: client,
		dorks:      compileDorks(),
	}
}

// Fetch retrieves and filters URLs from Wayback Machine
func (w *WaybackFetcher) Fetch(domain string) ([]WaybackResult, error) {
	// Fetch from CDX API
	rawURLs, err := w.fetchFromCDX(domain)
	if err != nil {
		return nil, err
	}

	// Filter for redirect-prone parameters
	return w.filterURLs(rawURLs), nil
}

// fetchFromCDX queries the Wayback Machine CDX API
// Maps to Python's fetcher() function in wayback.py
func (w *WaybackFetcher) fetchFromCDX(domain string) ([]string, error) {
	// Build CDX API URL
	currentYear := time.Now().Year()
	fromYear := currentYear - 2

	cdxURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s*&output=json&collapse=urlkey&filter=statuscode:200&limit=1000&from=%d&to=%d",
		url.QueryEscape(domain),
		fromYear,
		currentYear,
	)

	resp, body, err := w.httpClient.Get(cdxURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from Wayback Machine: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Wayback Machine returned status %d", resp.StatusCode)
	}

	// Parse JSON response
	// CDX API returns 2D array: [[header...], [row1...], [row2...], ...]
	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("failed to parse Wayback response: %w", err)
	}

	if len(results) < 2 {
		return nil, nil // No results (only header row or empty)
	}

	// Extract URLs (index 2 in each row is the original URL)
	var urls []string
	for i := 1; i < len(results); i++ { // Skip header row
		if len(results[i]) > 2 {
			// URL decode the URL
			decodedURL, err := url.QueryUnescape(results[i][2])
			if err != nil {
				decodedURL = results[i][2] // Use original if decode fails
			}
			urls = append(urls, decodedURL)
		}
	}

	return urls, nil
}

// filterURLs filters URLs matching redirect-prone parameter patterns
// Maps to Python's getURLs() filtering logic in wayback.py
func (w *WaybackFetcher) filterURLs(urls []string) []WaybackResult {
	var results []WaybackResult
	seen := make(map[string]bool)

	for _, rawURL := range urls {
		if seen[rawURL] {
			continue
		}

		for _, dork := range w.dorks {
			if dork.MatchString(rawURL) {
				results = append(results, WaybackResult{
					URL:       rawURL,
					Timestamp: time.Now().Format(time.RFC3339),
				})
				seen[rawURL] = true
				break
			}
		}
	}

	return results
}

// compileDorks compiles wayback dork patterns
func compileDorks() []*regexp.Regexp {
	var compiled []*regexp.Regexp

	for _, pattern := range WaybackDorks {
		re, err := regexp.Compile("(?i)" + pattern) // Case insensitive
		if err != nil {
			continue // Skip invalid patterns
		}
		compiled = append(compiled, re)
	}

	return compiled
}
