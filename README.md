### Introduction

Oralyzer is a security tool that probes for Open Redirect vulnerabilities in websites. It fuzzes URLs with payloads to identify vulnerable redirect parameters.

### Features

Oralyzer can identify following types of Open Redirect Vulnerabilities:
 - Header Based (3xx redirects)
 - Javascript Based (DOM-based redirects)
 - Meta Tag Based (http-equiv refresh)

Additional features:
- CRLF Injection Detection
- Wayback Machine URL enumeration
- Concurrent scanning with configurable workers
- JSON output support
- Proxy support

### Installation

```bash
git clone https://github.com/szybnev/Oralyzer-go && cd Oralyzer && go build -o oralyzer .
```

### Usage

```bash
# Single URL scan
./oralyzer -u "http://example.com/?redirect=test"

# Multiple URLs from file with 20 concurrent workers
./oralyzer -l urls.txt -c 20

# CRLF injection scan
./oralyzer -u "http://example.com/?param=test" --crlf

# Fetch URLs from Wayback Machine
./oralyzer -u "example.com" --wayback

# JSON output with proxy
./oralyzer -u "http://example.com/?url=test" --json --proxy http://127.0.0.1:8080

# Save results to file
./oralyzer -u "http://example.com/?next=test" -o results.txt
```

### Flags

| Flag | Description |
|------|-------------|
| `-u, --url` | Single target URL |
| `-l, --list` | File with multiple URLs |
| `-p, --payloads` | Custom payloads file |
| `--crlf` | CRLF injection scan |
| `--wayback` | Fetch from archive.org |
| `--proxy` | Proxy URL |
| `-c, --concurrency` | Parallel workers (default: 10) |
| `-o, --output` | Output file |
| `--json` | JSON output |
| `-t, --timeout` | HTTP timeout (default: 10s) |
