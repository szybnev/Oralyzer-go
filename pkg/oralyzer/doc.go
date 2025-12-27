/*
Package oralyzer provides a Go library for detecting Open Redirect vulnerabilities,
CRLF injection, and harvesting URLs from the Wayback Machine.

# Installation

	go get github.com/r0075h3ll/oralyzer/pkg/oralyzer

# Quick Start

Scan a single URL for open redirect vulnerabilities:

	package main

	import (
		"context"
		"fmt"
		"log"

		"github.com/r0075h3ll/oralyzer/pkg/oralyzer"
	)

	func main() {
		ctx := context.Background()

		results, err := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?redirect=test")
		if err != nil {
			log.Fatal(err)
		}

		for _, r := range results {
			if r.Vulnerable {
				fmt.Printf("VULNERABLE: %s -> %s\n", r.URL, r.RedirectURL)
			}
		}
	}

# Scan Types

The library supports three scan modes:

  - Open Redirect: Detects header-based, JavaScript-based, and meta tag redirects
  - CRLF Injection: Tests for HTTP response splitting vulnerabilities
  - Wayback: Harvests potentially vulnerable URLs from the Wayback Machine

# Open Redirect Scanning

	// Scan single URL
	results, _ := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?url=test")

	// Scan multiple URLs
	urls := []string{"http://example.com/?url=test", "http://example.com/?redirect=test"}
	results, _ := oralyzer.ScanOpenRedirects(ctx, urls)

	// With custom options
	opts := &oralyzer.Config{
		Concurrency: 20,
		Timeout:     15 * time.Second,
		ProxyURL:    "http://127.0.0.1:8080",
	}
	results, _ := oralyzer.ScanOpenRedirectsWithOptions(ctx, urls, opts)

# CRLF Injection Scanning

	// Scan for CRLF injection
	results, _ := oralyzer.ScanCRLF(ctx, "http://example.com/?param=test")

	// Multiple URLs
	results, _ := oralyzer.ScanCRLFs(ctx, urls)

# Wayback Machine URL Harvesting

	// Fetch URLs from Wayback Machine
	waybackResults, _ := oralyzer.FetchWaybackURLs(ctx, "example.com")

	for _, r := range waybackResults {
		fmt.Println(r.URL)
	}

# Advanced Usage with Scanner

For more control over the scanning process:

	config := &oralyzer.Config{
		URLs:        []string{"http://example.com/?redirect=test"},
		Concurrency: 20,
		Timeout:     15 * time.Second,
		ProxyURL:    "http://127.0.0.1:8080",
		Mode:        oralyzer.ModeOpenRedirect,
	}

	scanner, err := oralyzer.NewScanner(config)
	if err != nil {
		log.Fatal(err)
	}

	// Option 1: Get all results at once
	results, err := scanner.Scan(ctx)

	// Option 2: Process results as they come in
	err = scanner.ScanWithCallback(ctx, func(result oralyzer.Result) {
		if result.Vulnerable {
			fmt.Printf("Found: %s\n", result.URL)
		}
	})

# Custom Payloads

	// Load payloads from file
	payloads, _ := oralyzer.LoadPayloadsFromFile("payloads.txt")

	config := &oralyzer.Config{
		URLs:     []string{"http://example.com/?url=test"},
		Payloads: payloads,
	}
	scanner, _ := oralyzer.NewScanner(config)

# Result Types

The Result struct contains:

  - URL: The tested URL with payload
  - OriginalURL: The original target URL
  - Payload: The payload used
  - Vulnerable: Whether vulnerability was found
  - VulnType: Type of vulnerability (header, javascript, meta, crlf)
  - StatusCode: HTTP response status code
  - RedirectURL: Redirect location for header-based redirects
  - SourcesSinks: DOM XSS sources/sinks found
  - Error: Any error message
  - Timestamp: When the scan was performed

# Utility Functions

	// Filter only vulnerable results
	vulnerable := oralyzer.FilterVulnerable(results)

	// Filter by vulnerability type
	headerBased := oralyzer.FilterByType(results, oralyzer.VulnHeaderRedirect)

	// Count vulnerable
	count := oralyzer.CountVulnerable(results)

	// Get unique vulnerable URLs
	urls := oralyzer.GetUniqueVulnerableURLs(results)

# Vulnerability Types

  - VulnHeaderRedirect: HTTP Location header redirect (3xx)
  - VulnJavaScript: JavaScript-based redirect (location.href, etc.)
  - VulnMetaTag: Meta refresh tag redirect
  - VulnCRLFInjection: CRLF/HTTP response splitting
  - VulnPageRefresh: Page refresh without vulnerability
*/
package oralyzer
