# Oralyzer Go Library API

Oralyzer provides a native Go library API for detecting Open Redirect vulnerabilities, CRLF injection, and harvesting URLs from the Wayback Machine.

## Installation

```bash
go get github.com/szybnev/Oralyzer-go/pkg/oralyzer
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    // Scan for open redirects
    results, err := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?redirect=test")
    if err != nil {
        log.Fatal(err)
    }

    // Print vulnerable URLs
    for _, r := range oralyzer.FilterVulnerable(results) {
        fmt.Printf("[%s] %s -> %s\n", r.VulnType, r.URL, r.RedirectURL)
    }
}
```

## API Reference

### High-Level Functions

#### Open Redirect Scanning

```go
// Scan single URL for open redirect vulnerabilities
func ScanOpenRedirect(ctx context.Context, targetURL string) ([]Result, error)

// Scan multiple URLs
func ScanOpenRedirects(ctx context.Context, urls []string) ([]Result, error)

// Scan with custom options
func ScanOpenRedirectsWithOptions(ctx context.Context, urls []string, opts *Config) ([]Result, error)
```

#### CRLF Injection Scanning

```go
// Scan single URL for CRLF injection
func ScanCRLF(ctx context.Context, targetURL string) ([]Result, error)

// Scan multiple URLs
func ScanCRLFs(ctx context.Context, urls []string) ([]Result, error)

// Scan with custom options
func ScanCRLFsWithOptions(ctx context.Context, urls []string, opts *Config) ([]Result, error)
```

#### Wayback Machine URL Harvesting

```go
// Fetch potentially vulnerable URLs from Wayback Machine
func FetchWaybackURLs(ctx context.Context, domain string) ([]WaybackResult, error)

// Fetch with custom options
func FetchWaybackURLsWithOptions(ctx context.Context, domain string, opts *Config) ([]WaybackResult, error)
```

### Scanner (Advanced Usage)

For more control over the scanning process:

```go
// Create a new scanner
func NewScanner(config *Config) (*Scanner, error)

// Methods on Scanner:

// Scan performs scan and returns all results
func (s *Scanner) Scan(ctx context.Context) ([]Result, error)

// ScanWithCallback calls handler for each result (streaming)
func (s *Scanner) ScanWithCallback(ctx context.Context, handler ResultHandler) error

// ScanURL scans a single URL
func (s *Scanner) ScanURL(ctx context.Context, targetURL string) ([]Result, error)

// ScanURLs scans multiple URLs
func (s *Scanner) ScanURLs(ctx context.Context, urls []string) ([]Result, error)
```

### Utility Functions

```go
// Load payloads from external file
func LoadPayloadsFromFile(path string) ([]string, error)

// Filter only vulnerable results
func FilterVulnerable(results []Result) []Result

// Filter by vulnerability type
func FilterByType(results []Result, vulnType VulnerabilityType) []Result

// Count vulnerable results
func CountVulnerable(results []Result) int

// Get unique vulnerable original URLs
func GetUniqueVulnerableURLs(results []Result) []string

// Add http:// scheme if missing
func EnsureScheme(rawURL string) string
```

## Types

### Config

```go
type Config struct {
    // URLs to scan
    URLs []string

    // Custom payloads (optional, uses defaults if empty)
    Payloads []string

    // Proxy URL (e.g., "http://127.0.0.1:8080")
    ProxyURL string

    // Number of parallel workers (default: 10)
    Concurrency int

    // HTTP request timeout (default: 10s)
    Timeout time.Duration

    // Scan mode: ModeOpenRedirect, ModeCRLF, or ModeWayback
    Mode ScanMode

    // Follow HTTP redirects (default: false to capture redirects)
    FollowRedirects bool

    // Skip TLS certificate verification (default: true)
    InsecureSkipVerify bool
}
```

### Result

```go
type Result struct {
    // Tested URL with payload
    URL string `json:"url"`

    // Original target URL before payload injection
    OriginalURL string `json:"original_url,omitempty"`

    // Payload that was used
    Payload string `json:"payload,omitempty"`

    // Whether vulnerability was found
    Vulnerable bool `json:"vulnerable"`

    // Type of vulnerability found
    VulnType VulnerabilityType `json:"vulnerability_type,omitempty"`

    // HTTP response status code
    StatusCode int `json:"status_code"`

    // Redirect location for header-based redirects
    RedirectURL string `json:"redirect_url,omitempty"`

    // DOM XSS sources/sinks found in response
    SourcesSinks []string `json:"sources_sinks,omitempty"`

    // Error message if any
    Error string `json:"error,omitempty"`

    // When the scan was performed
    Timestamp time.Time `json:"timestamp"`
}
```

### WaybackResult

```go
type WaybackResult struct {
    // Archived URL
    URL string `json:"url"`

    // Timestamp when fetched
    Timestamp string `json:"timestamp"`
}
```

### ScanMode

```go
type ScanMode int

const (
    ModeOpenRedirect ScanMode = iota  // Open redirect scan
    ModeCRLF                          // CRLF injection scan
    ModeWayback                       // Wayback Machine fetch
)
```

### VulnerabilityType

```go
type VulnerabilityType string

const (
    VulnNone           VulnerabilityType = ""
    VulnHeaderRedirect VulnerabilityType = "header_based_redirect"
    VulnJavaScript     VulnerabilityType = "javascript_based_redirect"
    VulnMetaTag        VulnerabilityType = "meta_tag_redirect"
    VulnCRLFInjection  VulnerabilityType = "crlf_injection"
    VulnPageRefresh    VulnerabilityType = "page_refresh_only"
)
```

### ResultHandler

```go
// Callback function for processing scan results
type ResultHandler func(Result)
```

## Examples

### Basic Open Redirect Scan

```go
package main

import (
    "context"
    "fmt"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    results, err := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?url=test")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Scanned %d URLs, %d vulnerable\n",
        len(results), oralyzer.CountVulnerable(results))

    for _, r := range oralyzer.FilterVulnerable(results) {
        fmt.Printf("VULNERABLE: %s\n  Type: %s\n  Redirect: %s\n  Payload: %s\n\n",
            r.URL, r.VulnType, r.RedirectURL, r.Payload)
    }
}
```

### Scan with Custom Options

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    urls := []string{
        "http://example.com/?redirect=test",
        "http://example.com/?url=test",
        "http://example.com/?next=test",
    }

    opts := &oralyzer.Config{
        Concurrency: 20,
        Timeout:     15 * time.Second,
        ProxyURL:    "http://127.0.0.1:8080",
    }

    results, err := oralyzer.ScanOpenRedirectsWithOptions(ctx, urls, opts)
    if err != nil {
        panic(err)
    }

    for _, r := range oralyzer.FilterVulnerable(results) {
        fmt.Printf("[%s] %s\n", r.VulnType, r.URL)
    }
}
```

### Streaming Results with Callback

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    config := &oralyzer.Config{
        URLs:        []string{"http://example.com/?url=test"},
        Concurrency: 10,
        Timeout:     10 * time.Second,
        Mode:        oralyzer.ModeOpenRedirect,
    }

    scanner, err := oralyzer.NewScanner(config)
    if err != nil {
        panic(err)
    }

    err = scanner.ScanWithCallback(ctx, func(result oralyzer.Result) {
        if result.Vulnerable {
            fmt.Printf("FOUND: %s -> %s\n", result.URL, result.RedirectURL)
        } else if result.Error != "" {
            fmt.Printf("ERROR: %s - %s\n", result.URL, result.Error)
        }
    })
    if err != nil {
        panic(err)
    }
}
```

### CRLF Injection Scan

```go
package main

import (
    "context"
    "fmt"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    results, err := oralyzer.ScanCRLF(ctx, "http://example.com/?param=test")
    if err != nil {
        panic(err)
    }

    for _, r := range oralyzer.FilterVulnerable(results) {
        fmt.Printf("CRLF Injection found!\n  URL: %s\n  Payload: %s\n",
            r.URL, r.Payload)
    }
}
```

### Wayback Machine URL Harvesting

```go
package main

import (
    "context"
    "fmt"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    results, err := oralyzer.FetchWaybackURLs(ctx, "example.com")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Found %d potentially vulnerable URLs:\n", len(results))
    for _, r := range results {
        fmt.Println(r.URL)
    }
}
```

### Custom Payloads

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    // Load payloads from file
    payloads, err := oralyzer.LoadPayloadsFromFile("my_payloads.txt")
    if err != nil {
        panic(err)
    }

    // Or define inline
    payloads = []string{
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2f..",
    }

    config := &oralyzer.Config{
        URLs:        []string{"http://example.com/?redirect=test"},
        Payloads:    payloads,
        Concurrency: 10,
        Timeout:     10 * time.Second,
    }

    scanner, err := oralyzer.NewScanner(config)
    if err != nil {
        panic(err)
    }

    results, err := scanner.Scan(ctx)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Tested %d payloads, found %d vulnerabilities\n",
        len(payloads), oralyzer.CountVulnerable(results))
}
```

### Integration with Other Tools

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "github.com/szybnev/Oralyzer-go/pkg/oralyzer"
)

func main() {
    ctx := context.Background()

    results, _ := oralyzer.ScanOpenRedirect(ctx, "http://example.com/?url=test")

    // Export to JSON
    vulnerable := oralyzer.FilterVulnerable(results)
    jsonData, _ := json.MarshalIndent(vulnerable, "", "  ")
    os.WriteFile("results.json", jsonData, 0644)

    // Get unique vulnerable URLs for further testing
    uniqueURLs := oralyzer.GetUniqueVulnerableURLs(results)
    for _, url := range uniqueURLs {
        fmt.Println(url)
    }
}
```

## Default Payloads

The library includes ~50 default open redirect payloads covering:

- Protocol-relative URLs (`//evil.com`)
- Absolute URLs (`https://evil.com`)
- URL encoding bypasses (`%2f..`, `%E3%80%82`)
- Backslash tricks (`/\evil.com`)
- Unicode bypasses (`。evil.com`)
- Whitespace bypasses (`/%09/evil.com`)
- Port tricks (`//evil.com:80`)

Plus 25 CRLF injection payloads and 21 Wayback dork patterns.

## Thread Safety

- `Scanner` is safe for concurrent use
- Results are collected through channels
- The `ScanWithCallback` handler is called sequentially

## Error Handling

Results include an `Error` field for per-URL errors (timeouts, connection failures, etc.). The main `Scan` functions return errors for configuration issues or fatal problems.

```go
results, err := oralyzer.ScanOpenRedirect(ctx, url)
if err != nil {
    // Configuration or fatal error
    log.Fatal(err)
}

for _, r := range results {
    if r.Error != "" {
        // Per-URL error (timeout, connection refused, etc.)
        log.Printf("Error scanning %s: %s", r.URL, r.Error)
        continue
    }
    // Process result
}
```
