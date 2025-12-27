// Package oralyzer provides a Go library for detecting Open Redirect vulnerabilities,
// CRLF injection, and harvesting URLs from the Wayback Machine.
//
// # Quick Start
//
// Scan a single URL for open redirect:
//
//	results, err := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?redirect=test")
//
// Scan for CRLF injection:
//
//	results, err := oralyzer.ScanCRLF(ctx, "http://example.com/?param=test")
//
// Fetch URLs from Wayback Machine:
//
//	urls, err := oralyzer.FetchWaybackURLs(ctx, "example.com")
//
// # Advanced Usage
//
// For more control, create a Scanner with custom configuration:
//
//	config := &oralyzer.Config{
//	    URLs:        []string{"http://example.com/?url=test"},
//	    Concurrency: 20,
//	    Timeout:     15 * time.Second,
//	    ProxyURL:    "http://127.0.0.1:8080",
//	}
//	scanner, err := oralyzer.NewScanner(config)
//	results, err := scanner.Scan(ctx)
package oralyzer

import (
	"context"
	"time"
)

// ScanOpenRedirect scans a single URL for open redirect vulnerabilities.
// This is a convenience function for quick scans.
func ScanOpenRedirect(ctx context.Context, targetURL string) ([]Result, error) {
	return ScanOpenRedirects(ctx, []string{targetURL})
}

// ScanOpenRedirects scans multiple URLs for open redirect vulnerabilities.
func ScanOpenRedirects(ctx context.Context, urls []string) ([]Result, error) {
	return ScanOpenRedirectsWithOptions(ctx, urls, nil)
}

// ScanOpenRedirectsWithOptions scans URLs with custom configuration.
func ScanOpenRedirectsWithOptions(ctx context.Context, urls []string, opts *Config) ([]Result, error) {
	config := &Config{
		URLs:        urls,
		Mode:        ModeOpenRedirect,
		Concurrency: 10,
		Timeout:     10 * time.Second,
	}

	if opts != nil {
		if opts.Concurrency > 0 {
			config.Concurrency = opts.Concurrency
		}
		if opts.Timeout > 0 {
			config.Timeout = opts.Timeout
		}
		if opts.ProxyURL != "" {
			config.ProxyURL = opts.ProxyURL
		}
		if len(opts.Payloads) > 0 {
			config.Payloads = opts.Payloads
		}
		config.FollowRedirects = opts.FollowRedirects
		config.InsecureSkipVerify = opts.InsecureSkipVerify
	}

	scanner, err := NewScanner(config)
	if err != nil {
		return nil, err
	}

	return scanner.Scan(ctx)
}

// ScanCRLF scans a single URL for CRLF injection vulnerabilities.
func ScanCRLF(ctx context.Context, targetURL string) ([]Result, error) {
	return ScanCRLFs(ctx, []string{targetURL})
}

// ScanCRLFs scans multiple URLs for CRLF injection vulnerabilities.
func ScanCRLFs(ctx context.Context, urls []string) ([]Result, error) {
	return ScanCRLFsWithOptions(ctx, urls, nil)
}

// ScanCRLFsWithOptions scans URLs for CRLF injection with custom configuration.
func ScanCRLFsWithOptions(ctx context.Context, urls []string, opts *Config) ([]Result, error) {
	config := &Config{
		URLs:        urls,
		Mode:        ModeCRLF,
		Concurrency: 10,
		Timeout:     10 * time.Second,
	}

	if opts != nil {
		if opts.Concurrency > 0 {
			config.Concurrency = opts.Concurrency
		}
		if opts.Timeout > 0 {
			config.Timeout = opts.Timeout
		}
		if opts.ProxyURL != "" {
			config.ProxyURL = opts.ProxyURL
		}
		config.FollowRedirects = opts.FollowRedirects
		config.InsecureSkipVerify = opts.InsecureSkipVerify
	}

	scanner, err := NewScanner(config)
	if err != nil {
		return nil, err
	}

	return scanner.Scan(ctx)
}

// FetchWaybackURLs fetches URLs from the Wayback Machine for a domain.
func FetchWaybackURLs(ctx context.Context, domain string) ([]WaybackResult, error) {
	return FetchWaybackURLsWithOptions(ctx, domain, nil)
}

// FetchWaybackURLsWithOptions fetches URLs from Wayback Machine with custom configuration.
func FetchWaybackURLsWithOptions(ctx context.Context, domain string, opts *Config) ([]WaybackResult, error) {
	config := &Config{
		Timeout: 30 * time.Second,
	}

	if opts != nil {
		if opts.Timeout > 0 {
			config.Timeout = opts.Timeout
		}
		if opts.ProxyURL != "" {
			config.ProxyURL = opts.ProxyURL
		}
		config.InsecureSkipVerify = opts.InsecureSkipVerify
	}

	httpClient, err := newHTTPClient(config)
	if err != nil {
		return nil, err
	}

	fetcher := NewWaybackFetcher(httpClient)
	return fetcher.Fetch(domain)
}

// FilterVulnerable filters results to only include vulnerable URLs.
func FilterVulnerable(results []Result) []Result {
	var vulnerable []Result
	for _, r := range results {
		if r.Vulnerable {
			vulnerable = append(vulnerable, r)
		}
	}
	return vulnerable
}

// FilterByType filters results by vulnerability type.
func FilterByType(results []Result, vulnType VulnerabilityType) []Result {
	var filtered []Result
	for _, r := range results {
		if r.VulnType == vulnType {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// CountVulnerable returns the count of vulnerable results.
func CountVulnerable(results []Result) int {
	count := 0
	for _, r := range results {
		if r.Vulnerable {
			count++
		}
	}
	return count
}

// GetUniqueVulnerableURLs returns unique vulnerable original URLs.
func GetUniqueVulnerableURLs(results []Result) []string {
	seen := make(map[string]bool)
	var urls []string

	for _, r := range results {
		if r.Vulnerable {
			url := r.OriginalURL
			if url == "" {
				url = r.URL
			}
			if !seen[url] {
				seen[url] = true
				urls = append(urls, url)
			}
		}
	}

	return urls
}
