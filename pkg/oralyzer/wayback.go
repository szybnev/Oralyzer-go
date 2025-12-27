package oralyzer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// NewWaybackFetcher creates a new Wayback fetcher.
func NewWaybackFetcher(client *httpClient) *WaybackFetcher {
	return &WaybackFetcher{
		httpClient: client,
		dorks:      compileDorks(),
	}
}

// Fetch retrieves and filters URLs from Wayback Machine.
func (w *WaybackFetcher) Fetch(domain string) ([]WaybackResult, error) {
	rawURLs, err := w.fetchFromCDX(domain)
	if err != nil {
		return nil, err
	}

	return w.filterURLs(rawURLs), nil
}

// fetchFromCDX queries the Wayback Machine CDX API.
func (w *WaybackFetcher) fetchFromCDX(domain string) ([]string, error) {
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

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("failed to parse Wayback response: %w", err)
	}

	if len(results) < 2 {
		return nil, nil
	}

	var urls []string
	for i := 1; i < len(results); i++ {
		if len(results[i]) > 2 {
			decodedURL, err := url.QueryUnescape(results[i][2])
			if err != nil {
				decodedURL = results[i][2]
			}
			urls = append(urls, decodedURL)
		}
	}

	return urls, nil
}

// filterURLs filters URLs matching redirect-prone parameter patterns.
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

// compileDorks compiles wayback dork patterns.
func compileDorks() []*regexp.Regexp {
	var compiled []*regexp.Regexp

	for _, pattern := range WaybackDorks {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}

	return compiled
}
