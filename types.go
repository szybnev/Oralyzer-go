package main

import (
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

// ScanMode represents the type of scan to perform
type ScanMode int

const (
	ModeOpenRedirect ScanMode = iota
	ModeCRLF
	ModeWayback
)

// VulnerabilityType categorizes the type of redirect vulnerability
type VulnerabilityType string

const (
	VulnNone           VulnerabilityType = ""
	VulnHeaderRedirect VulnerabilityType = "header_based_redirect"
	VulnJavaScript     VulnerabilityType = "javascript_based_redirect"
	VulnMetaTag        VulnerabilityType = "meta_tag_redirect"
	VulnCRLFInjection  VulnerabilityType = "crlf_injection"
	VulnPageRefresh    VulnerabilityType = "page_refresh_only"
)

// Config holds all configuration options
type Config struct {
	URLs        []string
	PayloadFile string
	ProxyURL    string
	UseProxy    bool
	Concurrency int
	Timeout     time.Duration
	OutputFile  string
	JSONOutput  bool
	ScanMode    ScanMode
}

// ScanResult represents the outcome of scanning a single URL
type ScanResult struct {
	URL          string            `json:"url"`
	OriginalURL  string            `json:"original_url,omitempty"`
	Payload      string            `json:"payload,omitempty"`
	Vulnerable   bool              `json:"vulnerable"`
	VulnType     VulnerabilityType `json:"vulnerability_type,omitempty"`
	StatusCode   int               `json:"status_code"`
	RedirectURL  string            `json:"redirect_url,omitempty"`
	SourcesSinks []string          `json:"sources_sinks,omitempty"`
	Error        string            `json:"error,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

// ScanJob represents a unit of work for the worker pool
type ScanJob struct {
	URL     string
	BaseURL string
	Payload string
	Params  map[string]string
	Mode    ScanMode
}

// HTTPClient wraps http.Client with custom configuration
type HTTPClient struct {
	client     *http.Client
	userAgents []string
	proxyURL   string
}

// Scanner manages the scanning process
type Scanner struct {
	config      *Config
	httpClient  *HTTPClient
	payloads    *PayloadManager
	detector    *Detector
	crlfScanner *CRLFScanner
	jobs        chan ScanJob
	results     chan ScanResult
	wg          sync.WaitGroup
	output      *OutputManager
}

// PayloadManager handles payload loading and generation
type PayloadManager struct {
	basePayloads []string
}

// Detector analyzes HTTP responses for vulnerabilities
type Detector struct {
	payloadPattern *regexp.Regexp
	sourcesSinksRE *regexp.Regexp
	payloads       []string
}

// CRLFScanner handles CRLF injection testing
type CRLFScanner struct {
	payloads   []string
	httpClient *HTTPClient
}

// WaybackFetcher retrieves URLs from the Wayback Machine
type WaybackFetcher struct {
	httpClient *HTTPClient
	dorks      []*regexp.Regexp
}

// WaybackResult represents a URL fetched from Wayback Machine
type WaybackResult struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
}

// OutputManager handles result output to terminal, file, and JSON
type OutputManager struct {
	jsonMode   bool
	outputFile *os.File
	results    []ScanResult
	mu         sync.Mutex
}
