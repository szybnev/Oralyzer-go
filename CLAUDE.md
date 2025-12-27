# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Oralyzer is a Go-based security testing tool for detecting Open Redirect vulnerabilities in web applications. It fuzzes URLs with payloads to identify header-based, JavaScript-based, and meta tag-based redirections. It also includes CRLF injection detection and Wayback Machine URL harvesting.

**Oralyzer can be used both as a CLI tool and as a Go library.**

## Build and Run (CLI)

```bash
# Build
go build -o oralyzer .

# Run
./oralyzer -u "http://example.com/?redirect=test"
./oralyzer -l urls.txt -c 20 -o results.txt
./oralyzer -u "http://example.com/?param=test" --crlf
./oralyzer -u "example.com" --wayback
./oralyzer -u "http://example.com/?url=test" --json --proxy http://127.0.0.1:8080
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-u, --url` | Single target URL |
| `-l, --list` | File with multiple URLs |
| `-p, --payloads` | Custom payloads file (default: embedded) |
| `--crlf` | CRLF injection scan mode |
| `--wayback` | Fetch URLs from archive.org |
| `--proxy` | Proxy URL (e.g., http://127.0.0.1:8080) |
| `-c, --concurrency` | Number of parallel workers (default: 10) |
| `-o, --output` | Output file path |
| `--json` | JSON output format |
| `-t, --timeout` | HTTP timeout (default: 10s) |

## Library API Usage

### Installation

```bash
go get github.com/szybnev/Oralyzer-go/pkg/oralyzer
```

### Quick Start

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

    for _, r := range results {
        if r.Vulnerable {
            fmt.Printf("VULNERABLE: %s -> %s\n", r.URL, r.RedirectURL)
        }
    }
}
```

### API Functions

#### Open Redirect Scanning

```go
// Single URL
results, err := oralyzer.ScanOpenRedirect(ctx, url)

// Multiple URLs
results, err := oralyzer.ScanOpenRedirects(ctx, urls)

// With options
opts := &oralyzer.Config{
    Concurrency: 20,
    Timeout:     15 * time.Second,
    ProxyURL:    "http://127.0.0.1:8080",
}
results, err := oralyzer.ScanOpenRedirectsWithOptions(ctx, urls, opts)
```

#### CRLF Injection Scanning

```go
results, err := oralyzer.ScanCRLF(ctx, url)
results, err := oralyzer.ScanCRLFs(ctx, urls)
results, err := oralyzer.ScanCRLFsWithOptions(ctx, urls, opts)
```

#### Wayback Machine URL Harvesting

```go
waybackResults, err := oralyzer.FetchWaybackURLs(ctx, "example.com")
waybackResults, err := oralyzer.FetchWaybackURLsWithOptions(ctx, domain, opts)
```

#### Advanced Scanner Usage

```go
config := &oralyzer.Config{
    URLs:        []string{"http://example.com/?url=test"},
    Concurrency: 20,
    Timeout:     15 * time.Second,
    ProxyURL:    "http://127.0.0.1:8080",
    Mode:        oralyzer.ModeOpenRedirect, // or ModeCRLF
}

scanner, err := oralyzer.NewScanner(config)

// Get all results
results, err := scanner.Scan(ctx)

// Or process as they come
err = scanner.ScanWithCallback(ctx, func(result oralyzer.Result) {
    if result.Vulnerable {
        fmt.Printf("Found: %s\n", result.URL)
    }
})
```

#### Custom Payloads

```go
payloads, err := oralyzer.LoadPayloadsFromFile("payloads.txt")
config := &oralyzer.Config{
    URLs:     urls,
    Payloads: payloads,
}
```

#### Utility Functions

```go
vulnerable := oralyzer.FilterVulnerable(results)
headerBased := oralyzer.FilterByType(results, oralyzer.VulnHeaderRedirect)
count := oralyzer.CountVulnerable(results)
urls := oralyzer.GetUniqueVulnerableURLs(results)
```

### Vulnerability Types

| Constant | Description |
|----------|-------------|
| `VulnHeaderRedirect` | HTTP Location header redirect (3xx) |
| `VulnJavaScript` | JavaScript-based redirect |
| `VulnMetaTag` | Meta refresh tag redirect |
| `VulnCRLFInjection` | CRLF/HTTP response splitting |
| `VulnPageRefresh` | Page refresh without vulnerability |

### Result Struct

```go
type Result struct {
    URL          string            // Tested URL with payload
    OriginalURL  string            // Original target URL
    Payload      string            // Payload used
    Vulnerable   bool              // Vulnerability found
    VulnType     VulnerabilityType // Type of vulnerability
    StatusCode   int               // HTTP status code
    RedirectURL  string            // Redirect location
    SourcesSinks []string          // DOM XSS sources/sinks
    Error        string            // Error message
    Timestamp    time.Time         // Scan timestamp
}
```

## Architecture

| Path | Responsibility |
|------|----------------|
| `main.go` | Cobra CLI, entry point |
| `pkg/oralyzer/oralyzer.go` | High-level library API |
| `pkg/oralyzer/scanner.go` | Worker pool orchestration |
| `pkg/oralyzer/http.go` | HTTP client with proxy, User-Agent rotation |
| `pkg/oralyzer/detector.go` | Redirect detection (header/JS/meta tag) |
| `pkg/oralyzer/crlf.go` | CRLF injection scanner |
| `pkg/oralyzer/wayback.go` | Wayback Machine CDX API fetcher |
| `pkg/oralyzer/payload.go` | Payload loading and generation |
| `pkg/oralyzer/types.go` | Type definitions |
| `pkg/oralyzer/patterns.go` | Constants: DOM sinks, User-Agents, payloads |

## Key Patterns

- **Concurrency**: Worker pool with buffered channels (`jobs`, `results`)
- **Payloads**: Default payloads in `patterns.go`, custom via `LoadPayloadsFromFile`
- **HTTP**: `CheckRedirect` returns `ErrUseLastResponse` to capture redirects
- **Detection**: Regex matching for payloads in script tags and meta refresh
- **Callback API**: `ScanWithCallback` for streaming results
