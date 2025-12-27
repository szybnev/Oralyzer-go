package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ANSI color codes (matching Python's color scheme)
const (
	ColorReset  = "\033[00m"
	ColorRed    = "\033[91m"
	ColorGreen  = "\033[92m"
	ColorYellow = "\033[93m"
	ColorBold   = "\033[1m"
)

// Output prefixes (matching Python's good, bad, info)
var (
	PrefixGood  = ColorGreen + "[+]" + ColorReset
	PrefixBad   = ColorRed + "[-]" + ColorReset
	PrefixInfo  = ColorYellow + "[!]" + ColorReset
	ArrowSymbol = ColorRed + "->" + ColorReset
)

// NewOutputManager creates an output manager
func NewOutputManager(config *Config) (*OutputManager, error) {
	om := &OutputManager{
		jsonMode: config.JSONOutput,
		results:  make([]ScanResult, 0),
	}

	if config.OutputFile != "" {
		file, err := os.Create(config.OutputFile)
		if err != nil {
			return nil, err
		}
		om.outputFile = file
	}

	return om, nil
}

// Write outputs a single result
func (om *OutputManager) Write(result ScanResult) {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.results = append(om.results, result)

	if om.jsonMode {
		om.writeJSON(result)
	} else {
		om.writeTerminal(result)
	}
}

// writeTerminal outputs colored terminal output
func (om *OutputManager) writeTerminal(result ScanResult) {
	if result.Error != "" {
		if strings.Contains(result.Error, "timeout") {
			fmt.Printf("[%sTimeout%s] %s\n", ColorRed, ColorReset, result.URL)
		} else {
			fmt.Printf("%s Connection Error :: %s\n", PrefixBad, result.URL)
		}
		om.writeToFile(result)
		return
	}

	if !result.Vulnerable && result.VulnType == VulnNone {
		if isErrorCode(result.StatusCode) {
			fmt.Printf("%s %s [%s%d%s]\n", PrefixBad, result.URL, ColorRed, result.StatusCode, ColorReset)
		} else {
			fmt.Printf("%s Found nothing :: %s\n", PrefixBad, result.URL)
		}
		om.writeToFile(result)
		return
	}

	switch result.VulnType {
	case VulnHeaderRedirect:
		fmt.Printf("%s Header Based Redirection : %s %s  %s\n",
			PrefixGood, result.URL, ArrowSymbol, result.RedirectURL)

	case VulnJavaScript:
		fmt.Printf("%s Javascript Based Redirection\n", PrefixGood)
		if len(result.SourcesSinks) > 0 {
			fmt.Printf("%s Potentially Vulnerable Source/Sink(s) Found: %s%s%s\n",
				PrefixGood, ColorBold, strings.Join(result.SourcesSinks, " "), ColorReset)
		}

	case VulnMetaTag:
		fmt.Printf("%s Meta Tag Redirection\n", PrefixGood)

	case VulnCRLFInjection:
		fmt.Printf("%s HTTP Response Splitting found\n", PrefixGood)
		fmt.Printf("%s Payload : %s\n", PrefixInfo, result.Payload)

	case VulnPageRefresh:
		fmt.Printf("%s The page is only getting refreshed\n", PrefixBad)
	}

	// Write to file if configured
	om.writeToFile(result)
}

// writeJSON outputs JSON-formatted result
func (om *OutputManager) writeJSON(result ScanResult) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	fmt.Println(string(data))

	if om.outputFile != nil {
		om.outputFile.Write(data)
		om.outputFile.WriteString("\n")
	}
}

// writeToFile writes result to output file
func (om *OutputManager) writeToFile(result ScanResult) {
	if om.outputFile == nil {
		return
	}

	if om.jsonMode {
		// Already written in writeJSON
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
	om.outputFile.WriteString(line)
}

// Flush writes final summary and closes file
func (om *OutputManager) Flush() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Print summary
	vulnerable := 0
	errors := 0
	for _, r := range om.results {
		if r.Vulnerable {
			vulnerable++
		}
		if r.Error != "" {
			errors++
		}
	}

	fmt.Printf("\n%s Scan complete. %d/%d URLs vulnerable",
		PrefixInfo, vulnerable, len(om.results))
	if errors > 0 {
		fmt.Printf(" (%d errors)", errors)
	}
	fmt.Println()

	if om.outputFile != nil {
		// Write summary to file
		summary := fmt.Sprintf("\n# Summary: %d/%d vulnerable, %d errors\n",
			vulnerable, len(om.results), errors)
		om.outputFile.WriteString(summary)
		return om.outputFile.Close()
	}
	return nil
}

// PrintBanner prints the tool banner
func PrintBanner() {
	fmt.Println(ColorRed + "\n\tOralyzer" + ColorReset + "\n")
}

// PrintInfo prints an info message
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf(PrefixInfo+" "+format+"\n", args...)
}

// PrintGood prints a success message
func PrintGood(format string, args ...interface{}) {
	fmt.Printf(PrefixGood+" "+format+"\n", args...)
}

// PrintBad prints an error message
func PrintBad(format string, args ...interface{}) {
	fmt.Printf(PrefixBad+" "+format+"\n", args...)
}
