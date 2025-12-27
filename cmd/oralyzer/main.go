package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/szybnev/Oralyzer-go/pkg/oralyzer"
	"github.com/spf13/cobra"
)

// ANSI color codes
const (
	ColorReset  = "\033[00m"
	ColorRed    = "\033[91m"
	ColorGreen  = "\033[92m"
	ColorYellow = "\033[93m"
	ColorBold   = "\033[1m"
)

var (
	PrefixGood  = ColorGreen + "[+]" + ColorReset
	PrefixBad   = ColorRed + "[-]" + ColorReset
	PrefixInfo  = ColorYellow + "[!]" + ColorReset
	ArrowSymbol = ColorRed + "->" + ColorReset
)

var (
	targetURL    string
	listFile     string
	payloadFile  string
	crlfMode     bool
	waybackMode  bool
	proxyURL     string
	concurrency  int
	outputFile   string
	jsonOutput   bool
	timeout      time.Duration
	headers      []string
	retryEnabled bool
	verbose      bool
	quiet        bool
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
	rootCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom header (can be used multiple times: -H 'Cookie: x' -H 'Auth: y')")
	rootCmd.Flags().BoolVar(&retryEnabled, "retry", false, "Enable retry on 429/503 (delays: 10s, 30s, 60s)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output (show all requests)")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (only show vulnerabilities)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	if !quiet {
		printBanner()
	}

	if targetURL == "" && listFile == "" {
		fmt.Printf("%s Either -u (URL) or -l (list file) is required\n", PrefixBad)
		cmd.Help()
		return
	}

	if payloadFile != "" && (crlfMode || waybackMode) {
		fmt.Printf("%s '-p' can't be used with '--crlf' or '--wayback'\n", PrefixBad)
		return
	}

	if verbose && quiet {
		fmt.Printf("%s Cannot use --verbose and --quiet together\n", PrefixBad)
		return
	}

	// Load URLs
	urls, err := loadURLs(targetURL, listFile)
	if err != nil {
		fmt.Printf("%s %v\n", PrefixBad, err)
		return
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !quiet {
			fmt.Println("\nQuitting...")
		}
		cancel()
	}()

	// Handle Wayback mode
	if waybackMode {
		runWaybackMode(ctx, urls)
		return
	}

	// Parse custom headers
	customHeaders := parseHeaders(headers)

	// Build config
	config := &oralyzer.Config{
		URLs:         urls,
		ProxyURL:     proxyURL,
		Concurrency:  concurrency,
		Timeout:      timeout,
		Headers:      customHeaders,
		RetryEnabled: retryEnabled,
		Verbose:      verbose,
		Quiet:        quiet,
	}

	// Load custom payloads if specified
	if payloadFile != "" {
		payloads, err := oralyzer.LoadPayloadsFromFile(payloadFile)
		if err != nil {
			fmt.Printf("%s Failed to load payloads: %v\n", PrefixBad, err)
			return
		}
		config.Payloads = payloads
	}

	// Set scan mode
	if crlfMode {
		config.Mode = oralyzer.ModeCRLF
	} else {
		config.Mode = oralyzer.ModeOpenRedirect
	}

	// Create scanner
	scanner, err := oralyzer.NewScanner(config)
	if err != nil {
		fmt.Printf("%s Failed to create scanner: %v\n", PrefixBad, err)
		return
	}

	// Open output file if specified
	var outFile *os.File
	if outputFile != "" {
		outFile, err = os.Create(outputFile)
		if err != nil {
			fmt.Printf("%s Failed to create output file: %v\n", PrefixBad, err)
			return
		}
		defer outFile.Close()
	}

	// Stats
	var totalResults, vulnerableCount, errorCount int

	// Print scan info
	if !quiet {
		for _, url := range urls {
			fmt.Printf("%s Target: %s\n", PrefixInfo, url)
			if crlfMode {
				fmt.Printf("%s Scanning for CRLF injection\n", PrefixInfo)
			} else {
				fmt.Printf("%s Infusing payloads\n", PrefixInfo)
			}
		}
		if retryEnabled {
			fmt.Printf("%s Retry enabled (10s, 30s, 60s delays)\n", PrefixInfo)
		}
		if len(customHeaders) > 0 {
			fmt.Printf("%s Using %d custom header(s)\n", PrefixInfo, len(customHeaders))
		}
	}

	err = scanner.ScanWithCallback(ctx, func(result oralyzer.Result) {
		totalResults++
		if result.Vulnerable {
			vulnerableCount++
		}
		if result.Error != "" {
			errorCount++
		}

		// Output result based on mode
		if jsonOutput {
			if !quiet || result.Vulnerable {
				writeJSON(result, outFile)
			}
		} else {
			writeTerminalWithMode(result, outFile, verbose, quiet)
		}
	})

	if err != nil && err != context.Canceled {
		fmt.Printf("%s Scan error: %v\n", PrefixBad, err)
	}

	// Print summary
	if !quiet {
		fmt.Printf("\n%s Scan complete. %d/%d URLs vulnerable", PrefixInfo, vulnerableCount, totalResults)
		if errorCount > 0 {
			fmt.Printf(" (%d errors)", errorCount)
		}
		fmt.Println()
	}
}

// parseHeaders converts header strings to map
func parseHeaders(headerList []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headerList {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			result[key] = value
		}
	}
	return result
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

func runWaybackMode(ctx context.Context, urls []string) {
	config := &oralyzer.Config{
		ProxyURL: proxyURL,
		Timeout:  30 * time.Second,
	}

	for _, url := range urls {
		select {
		case <-ctx.Done():
			return
		default:
		}

		fmt.Printf("%s Getting juicy URLs from archive.org for %s\n", PrefixInfo, url)

		results, err := oralyzer.FetchWaybackURLsWithOptions(ctx, url, config)
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
		if outputFile != "" {
			outputPath = outputFile
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

func writeTerminalWithMode(result oralyzer.Result, outFile *os.File, verbose, quiet bool) {
	// Quiet mode: only show vulnerabilities
	if quiet {
		if result.Vulnerable {
			writeVulnerability(result)
		}
		writeToFile(result, outFile)
		return
	}

	// Handle errors
	if result.Error != "" {
		if verbose {
			if strings.Contains(result.Error, "timeout") {
				fmt.Printf("[%sTimeout%s] %s\n", ColorRed, ColorReset, result.URL)
			} else {
				fmt.Printf("%s Connection Error :: %s :: %s\n", PrefixBad, result.URL, result.Error)
			}
		}
		writeToFile(result, outFile)
		return
	}

	// Not vulnerable
	if !result.Vulnerable && result.VulnType == oralyzer.VulnNone {
		if verbose {
			if result.StatusCode >= 400 && result.StatusCode <= 410 {
				fmt.Printf("%s %s [%s%d%s]\n", PrefixBad, result.URL, ColorRed, result.StatusCode, ColorReset)
			} else {
				fmt.Printf("%s [%d] %s\n", PrefixBad, result.StatusCode, result.URL)
			}
		}
		writeToFile(result, outFile)
		return
	}

	// Vulnerable - always show
	writeVulnerability(result)
	writeToFile(result, outFile)
}

func writeVulnerability(result oralyzer.Result) {
	switch result.VulnType {
	case oralyzer.VulnHeaderRedirect:
		fmt.Printf("%s Header Based Redirection : %s %s  %s\n",
			PrefixGood, result.URL, ArrowSymbol, result.RedirectURL)

	case oralyzer.VulnJavaScript:
		fmt.Printf("%s Javascript Based Redirection : %s\n", PrefixGood, result.URL)
		if len(result.SourcesSinks) > 0 {
			fmt.Printf("%s Potentially Vulnerable Source/Sink(s) Found: %s%s%s\n",
				PrefixGood, ColorBold, strings.Join(result.SourcesSinks, " "), ColorReset)
		}

	case oralyzer.VulnMetaTag:
		fmt.Printf("%s Meta Tag Redirection : %s\n", PrefixGood, result.URL)

	case oralyzer.VulnCRLFInjection:
		fmt.Printf("%s HTTP Response Splitting found : %s\n", PrefixGood, result.URL)
		fmt.Printf("%s Payload : %s\n", PrefixInfo, result.Payload)

	case oralyzer.VulnPageRefresh:
		fmt.Printf("%s Page refresh (not vulnerable) : %s\n", PrefixBad, result.URL)
	}
}

func writeJSON(result oralyzer.Result, outFile *os.File) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	fmt.Println(string(data))

	if outFile != nil {
		outFile.Write(data)
		outFile.WriteString("\n")
	}
}

func writeToFile(result oralyzer.Result, outFile *os.File) {
	if outFile == nil {
		return
	}

	var line string
	if result.Vulnerable {
		line = fmt.Sprintf("[VULNERABLE] %s | %s | %s | Payload: %s\n",
			result.Timestamp.Format(time.RFC3339),
			result.URL,
			result.VulnType,
			result.Payload)
	} else if result.Error != "" {
		line = fmt.Sprintf("[ERROR] %s | %s | %s\n",
			result.Timestamp.Format(time.RFC3339),
			result.URL,
			result.Error)
	} else {
		line = fmt.Sprintf("[SAFE] %s | %s | %d\n",
			result.Timestamp.Format(time.RFC3339),
			result.URL,
			result.StatusCode)
	}
	outFile.WriteString(line)
}

func printBanner() {
	fmt.Println(ColorRed + "\n\tOralyzer" + ColorReset + "\n")
}
