# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Oralyzer is a Go-based security testing tool for detecting Open Redirect vulnerabilities in web applications. It fuzzes URLs with payloads to identify header-based, JavaScript-based, and meta tag-based redirections. It also includes CRLF injection detection and Wayback Machine URL harvesting.

## Build and Run

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

## Architecture

| File | Responsibility |
|------|----------------|
| `main.go` | Cobra CLI, entry point, argument validation |
| `scanner.go` | Worker pool orchestration, job dispatching |
| `http.go` | HTTP client with proxy, User-Agent rotation, SSL bypass |
| `detector.go` | Redirect detection (header/JS/meta tag), DOM XSS source/sink matching |
| `crlf.go` | CRLF injection scanner with 25 payloads |
| `wayback.go` | Wayback Machine CDX API fetcher with 22 dork patterns |
| `payload.go` | Payload loading (embedded), regex bypass generation |
| `output.go` | Terminal (colored), JSON, file output |
| `types.go` | All struct and type definitions |
| `patterns.go` | Constants: 126 DOM sinks, 9 User-Agents, dorks, CRLF payloads |

## Key Patterns

- **Concurrency**: Worker pool with buffered channels (`jobs`, `results`)
- **Payloads**: Embedded via `//go:embed payloads.txt`
- **HTTP**: `CheckRedirect` returns `ErrUseLastResponse` to capture redirects
- **Detection**: Regex matching for payloads in script tags and meta refresh
