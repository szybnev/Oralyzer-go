package main

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// NewDetector creates a new detector with compiled patterns
func NewDetector(payloads []string) *Detector {
	// Escape payloads for regex matching
	escapedPayloads := make([]string, len(payloads))
	for i, p := range payloads {
		escapedPayloads[i] = regexp.QuoteMeta(p)
	}

	payloadPattern := regexp.MustCompile("(?i)" + strings.Join(escapedPayloads, "|"))

	// Escape sources/sinks for regex matching
	escapedSinks := make([]string, len(DOMSourcesSinks))
	for i, s := range DOMSourcesSinks {
		escapedSinks[i] = regexp.QuoteMeta(s)
	}

	sourcesSinksRE := regexp.MustCompile(strings.Join(escapedSinks, "|"))

	return &Detector{
		payloadPattern: payloadPattern,
		sourcesSinksRE: sourcesSinksRE,
		payloads:       payloads,
	}
}

// Analyze checks a response for redirect vulnerabilities
// Maps to Python's check() function in oralyzer.py
func (d *Detector) Analyze(resp *http.Response, body []byte, finalURL string) ScanResult {
	result := ScanResult{
		URL:        finalURL,
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	// Check based on status code
	switch {
	case isRedirectCode(resp.StatusCode):
		return d.checkHeaderRedirect(resp, body, result)
	case resp.StatusCode == 200:
		return d.checkContentRedirect(body, result)
	case isErrorCode(resp.StatusCode):
		result.Error = "HTTP error"
		return result
	default:
		return result
	}
}

// checkHeaderRedirect examines 3xx responses
func (d *Detector) checkHeaderRedirect(resp *http.Response, body []byte, result ScanResult) ScanResult {
	location := resp.Header.Get("Location")

	// Check for meta tag redirect with payload in redirect response
	if d.hasMetaRedirect(body) && d.payloadPattern.Match(body) {
		result.Vulnerable = true
		result.VulnType = VulnMetaTag
		return result
	}

	// Header-based redirect
	if location != "" {
		result.Vulnerable = true
		result.VulnType = VulnHeaderRedirect
		result.RedirectURL = location
	}

	return result
}

// checkContentRedirect examines 200 responses for JS/meta redirects
func (d *Detector) checkContentRedirect(body []byte, result ScanResult) ScanResult {
	// Extract script tags and check for payload
	scriptContent := d.extractScriptContent(body)
	if d.payloadPattern.Match(scriptContent) {
		result.Vulnerable = true
		result.VulnType = VulnJavaScript
		result.SourcesSinks = d.findSourcesSinks(body)
		return result
	}

	// Check meta tag redirects
	if d.hasMetaRedirect(body) {
		if d.payloadPattern.Match(body) {
			result.Vulnerable = true
			result.VulnType = VulnMetaTag
		} else {
			// Page refresh without payload - not vulnerable
			result.VulnType = VulnPageRefresh
		}
		return result
	}

	return result
}

// extractScriptContent extracts content from all <script> tags
func (d *Detector) extractScriptContent(body []byte) []byte {
	var scriptContent bytes.Buffer

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return body // Fallback to full body if parsing fails
	}

	var extractScripts func(*html.Node)
	extractScripts = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// Get text content of script tag
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					scriptContent.WriteString(c.Data)
					scriptContent.WriteString(" ")
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractScripts(c)
		}
	}

	extractScripts(doc)
	return scriptContent.Bytes()
}

// hasMetaRedirect checks for http-equiv="refresh" meta tags
func (d *Detector) hasMetaRedirect(body []byte) bool {
	// Simple string check for performance
	bodyLower := bytes.ToLower(body)
	return bytes.Contains(bodyLower, []byte(`http-equiv="refresh"`)) ||
		bytes.Contains(bodyLower, []byte(`http-equiv='refresh'`))
}

// findSourcesSinks identifies DOM XSS sources/sinks in content
func (d *Detector) findSourcesSinks(body []byte) []string {
	matches := d.sourcesSinksRE.FindAllString(string(body), -1)

	// Remove duplicates
	seen := make(map[string]bool)
	var unique []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}

	return unique
}

// extractMetaTags extracts all <meta> tags content
func (d *Detector) extractMetaTags(body []byte) []byte {
	var metaContent bytes.Buffer

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var extractMetas func(*html.Node)
	extractMetas = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			for _, attr := range n.Attr {
				metaContent.WriteString(attr.Key)
				metaContent.WriteString("=")
				metaContent.WriteString(attr.Val)
				metaContent.WriteString(" ")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractMetas(c)
		}
	}

	extractMetas(doc)
	return metaContent.Bytes()
}

// isRedirectCode checks if status code is a redirect (300-310)
func isRedirectCode(code int) bool {
	return code >= 300 && code <= 310
}

// isErrorCode checks if status code is a client error (400-410)
func isErrorCode(code int) bool {
	return code >= 400 && code <= 410
}
