package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	// CLI flags
	targetURL   string
	listFile    string
	payloadFile string
	crlfMode    bool
	waybackMode bool
	proxyURL    string
	concurrency int
	outputFile  string
	jsonOutput  bool
	timeout     time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "oralyzer",
	Short: "Open Redirect Vulnerability Scanner",
	Long: `Oralyzer probes for Open Redirect vulnerabilities in websites.
It supports header-based, JavaScript-based, and meta tag-based redirect detection,
as well as CRLF injection scanning and Wayback Machine URL enumeration.`,
	Run: runScan,
}

func init() {
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Scan single target URL")
	rootCmd.Flags().StringVarP(&listFile, "list", "l", "", "Scan multiple targets from file")
	rootCmd.Flags().StringVarP(&payloadFile, "payloads", "p", "", "Custom payloads file (default: embedded)")
	rootCmd.Flags().BoolVar(&crlfMode, "crlf", false, "Scan for CRLF injection")
	rootCmd.Flags().BoolVar(&waybackMode, "wayback", false, "Fetch URLs from archive.org")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "Number of concurrent workers")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "HTTP request timeout")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	// Print banner
	PrintBanner()

	// Validate arguments
	if targetURL == "" && listFile == "" {
		fmt.Printf("%s Either -u (URL) or -l (list file) is required\n", PrefixBad)
		cmd.Help()
		return
	}

	if payloadFile != "" && (crlfMode || waybackMode) {
		fmt.Printf("%s '-p' can't be used with '--crlf' or '--wayback'\n", PrefixBad)
		return
	}

	// Build config
	config := &Config{
		PayloadFile: payloadFile,
		ProxyURL:    proxyURL,
		UseProxy:    proxyURL != "",
		Concurrency: concurrency,
		Timeout:     timeout,
		OutputFile:  outputFile,
		JSONOutput:  jsonOutput,
	}

	// Determine scan mode
	if crlfMode {
		config.ScanMode = ModeCRLF
	} else if waybackMode {
		config.ScanMode = ModeWayback
	} else {
		config.ScanMode = ModeOpenRedirect
	}

	// Load URLs
	var err error
	config.URLs, err = loadURLs(targetURL, listFile)
	if err != nil {
		fmt.Printf("%s %v\n", PrefixBad, err)
		return
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nQuitting...")
		cancel()
	}()

	// Handle Wayback mode separately
	if config.ScanMode == ModeWayback {
		runWaybackMode(ctx, config)
		return
	}

	// Create and run scanner
	scanner, err := NewScanner(config)
	if err != nil {
		fmt.Printf("%s Failed to create scanner: %v\n", PrefixBad, err)
		return
	}

	if err := scanner.Start(ctx); err != nil {
		if err != context.Canceled {
			fmt.Printf("%s Scan error: %v\n", PrefixBad, err)
		}
	}

	scanner.Stop()
}

func loadURLs(singleURL, listPath string) ([]string, error) {
	var urls []string

	if singleURL != "" {
		urls = append(urls, singleURL)
	}

	if listPath != "" {
		file, err := os.Open(listPath)
		if err != nil {
			return nil, fmt.Errorf("target file not found: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				urls = append(urls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading target file: %w", err)
		}
	}

	return urls, nil
}

func runWaybackMode(ctx context.Context, config *Config) {
	httpClient, err := NewHTTPClient(config)
	if err != nil {
		fmt.Printf("%s Failed to create HTTP client: %v\n", PrefixBad, err)
		return
	}

	fetcher := NewWaybackFetcher(httpClient)

	for _, url := range config.URLs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		fmt.Printf("%s Getting juicy URLs from archive.org for %s\n", PrefixInfo, url)

		results, err := fetcher.Fetch(url)
		if err != nil {
			fmt.Printf("%s Error fetching from Wayback: %v\n", PrefixBad, err)
			continue
		}

		if len(results) == 0 {
			fmt.Printf("%s No juicy URLs found\n", PrefixBad)
			continue
		}

		// Output results
		outputPath := fmt.Sprintf("wayback_%s.txt", sanitizeFilename(url))
		if config.OutputFile != "" {
			outputPath = config.OutputFile
		}

		file, err := os.Create(outputPath)
		if err != nil {
			fmt.Printf("%s Failed to create output file: %v\n", PrefixBad, err)
			continue
		}

		for _, result := range results {
			fmt.Printf("%s %s\n", PrefixGood, result.URL)
			file.WriteString(result.URL + "\n")
		}
		file.Close()

		fmt.Printf("%s Saved %d URLs to %s\n", PrefixInfo, len(results), outputPath)
	}
}

func sanitizeFilename(url string) string {
	// Simple sanitization for filename
	result := ""
	for _, c := range url {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result += string(c)
		} else if c == '.' || c == '/' || c == ':' {
			result += "_"
		}
	}
	if len(result) > 50 {
		result = result[:50]
	}
	return result
}
