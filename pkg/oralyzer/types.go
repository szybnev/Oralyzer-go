// Package oralyzer provides a Go library for detecting Open Redirect vulnerabilities,
// CRLF injection, and harvesting URLs from the Wayback Machine.
package oralyzer

import (
	"net/http"
	"regexp"
	"sync"
	"time"
)

// ScanMode represents the type of scan to perform.
type ScanMode int

const (
	// ModeOpenRedirect scans for open redirect vulnerabilities.
	ModeOpenRedirect ScanMode = iota
	// ModeCRLF scans for CRLF injection vulnerabilities.
	ModeCRLF
	// ModeWayback fetches URLs from the Wayback Machine.
	ModeWayback
)

// VulnerabilityType categorizes the type of redirect vulnerability.
type VulnerabilityType string

const (
	// VulnNone indicates no vulnerability was found.
	VulnNone VulnerabilityType = ""
	// VulnHeaderRedirect indicates a header-based redirect vulnerability.
	VulnHeaderRedirect VulnerabilityType = "header_based_redirect"
	// VulnJavaScript indicates a JavaScript-based redirect vulnerability.
	VulnJavaScript VulnerabilityType = "javascript_based_redirect"
	// VulnMetaTag indicates a meta tag redirect vulnerability.
	VulnMetaTag VulnerabilityType = "meta_tag_redirect"
	// VulnCRLFInjection indicates a CRLF injection vulnerability.
	VulnCRLFInjection VulnerabilityType = "crlf_injection"
	// VulnPageRefresh indicates a page refresh without vulnerability.
	VulnPageRefresh VulnerabilityType = "page_refresh_only"
)

// Config holds all configuration options for the scanner.
type Config struct {
	// URLs is the list of target URLs to scan.
	URLs []string
	// Payloads is an optional list of custom payloads.
	// If empty, embedded payloads will be used.
	Payloads []string
	// ProxyURL is the optional proxy URL (e.g., "http://127.0.0.1:8080").
	ProxyURL string
	// Concurrency is the number of parallel workers (default: 10).
	Concurrency int
	// Timeout is the HTTP request timeout (default: 10s).
	Timeout time.Duration
	// Mode specifies the scan mode (OpenRedirect, CRLF, or Wayback).
	Mode ScanMode
	// FollowRedirects determines whether to follow HTTP redirects.
	// Default is false to capture redirect responses.
	FollowRedirects bool
	// InsecureSkipVerify skips TLS certificate verification.
	// Default is true.
	InsecureSkipVerify bool
	// Headers contains custom HTTP headers to send with each request.
	Headers map[string]string
	// RetryEnabled enables automatic retry on 429/503 responses.
	// Default retry delays: 10s, 30s, 60s.
	RetryEnabled bool
	// Verbose enables detailed output logging.
	Verbose bool
	// Quiet suppresses all output except vulnerabilities.
	Quiet bool
}

// Result represents the outcome of scanning a single URL.
type Result struct {
	// URL is the tested URL with payload.
	URL string `json:"url"`
	// OriginalURL is the original target URL before payload injection.
	OriginalURL string `json:"original_url,omitempty"`
	// Payload is the payload that was used.
	Payload string `json:"payload,omitempty"`
	// Vulnerable indicates whether a vulnerability was found.
	Vulnerable bool `json:"vulnerable"`
	// VulnType is the type of vulnerability found.
	VulnType VulnerabilityType `json:"vulnerability_type,omitempty"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// RedirectURL is the Location header value for redirect vulnerabilities.
	RedirectURL string `json:"redirect_url,omitempty"`
	// SourcesSinks lists DOM XSS sources/sinks found in the response.
	SourcesSinks []string `json:"sources_sinks,omitempty"`
	// Error contains any error message.
	Error string `json:"error,omitempty"`
	// Timestamp is when the scan was performed.
	Timestamp time.Time `json:"timestamp"`
}

// WaybackResult represents a URL fetched from the Wayback Machine.
type WaybackResult struct {
	// URL is the archived URL.
	URL string `json:"url"`
	// Timestamp is when the URL was fetched.
	Timestamp string `json:"timestamp"`
}

// scanJob represents a unit of work for the worker pool.
type scanJob struct {
	URL     string
	BaseURL string
	Payload string
	Params  map[string]string
	Mode    ScanMode
}

// httpClient wraps http.Client with custom configuration.
type httpClient struct {
	client       *http.Client
	userAgents   []string
	proxyURL     string
	headers      map[string]string
	retryEnabled bool
	retryDelays  []time.Duration
}

// Scanner manages the scanning process.
type Scanner struct {
	config      *Config
	httpClient  *httpClient
	payloads    *PayloadManager
	detector    *Detector
	crlfScanner *CRLFScanner
	jobs        chan scanJob
	results     chan Result
	wg          sync.WaitGroup
}

// PayloadManager handles payload loading and generation.
type PayloadManager struct {
	basePayloads []string
}

// Detector analyzes HTTP responses for vulnerabilities.
type Detector struct {
	payloadPattern *regexp.Regexp
	sourcesSinksRE *regexp.Regexp
	payloads       []string
}

// CRLFScanner handles CRLF injection testing.
type CRLFScanner struct {
	payloads   []string
	httpClient *httpClient
}

// WaybackFetcher retrieves URLs from the Wayback Machine.
type WaybackFetcher struct {
	httpClient *httpClient
	dorks      []*regexp.Regexp
}

// ResultHandler is a callback function for processing scan results.
type ResultHandler func(Result)
