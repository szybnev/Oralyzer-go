package oralyzer

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// NewDetector creates a new detector with compiled patterns.
func NewDetector(payloads []string) *Detector {
	escapedPayloads := make([]string, len(payloads))
	for i, p := range payloads {
		escapedPayloads[i] = regexp.QuoteMeta(p)
	}

	payloadPattern := regexp.MustCompile("(?i)" + strings.Join(escapedPayloads, "|"))

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

// Analyze checks a response for redirect vulnerabilities.
func (d *Detector) Analyze(resp *http.Response, body []byte, finalURL string) Result {
	result := Result{
		URL:        finalURL,
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
	}

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

// checkHeaderRedirect examines 3xx responses.
func (d *Detector) checkHeaderRedirect(resp *http.Response, body []byte, result Result) Result {
	location := resp.Header.Get("Location")

	if d.hasMetaRedirect(body) && d.payloadPattern.Match(body) {
		result.Vulnerable = true
		result.VulnType = VulnMetaTag
		return result
	}

	if location != "" {
		result.Vulnerable = true
		result.VulnType = VulnHeaderRedirect
		result.RedirectURL = location
	}

	return result
}

// checkContentRedirect examines 200 responses for JS/meta redirects.
func (d *Detector) checkContentRedirect(body []byte, result Result) Result {
	scriptContent := d.extractScriptContent(body)
	if d.payloadPattern.Match(scriptContent) {
		result.Vulnerable = true
		result.VulnType = VulnJavaScript
		result.SourcesSinks = d.findSourcesSinks(body)
		return result
	}

	if d.hasMetaRedirect(body) {
		if d.payloadPattern.Match(body) {
			result.Vulnerable = true
			result.VulnType = VulnMetaTag
		} else {
			result.VulnType = VulnPageRefresh
		}
		return result
	}

	return result
}

// extractScriptContent extracts content from all <script> tags.
func (d *Detector) extractScriptContent(body []byte) []byte {
	var scriptContent bytes.Buffer

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return body
	}

	var extractScripts func(*html.Node)
	extractScripts = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
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

// hasMetaRedirect checks for http-equiv="refresh" meta tags.
func (d *Detector) hasMetaRedirect(body []byte) bool {
	bodyLower := bytes.ToLower(body)
	return bytes.Contains(bodyLower, []byte(`http-equiv="refresh"`)) ||
		bytes.Contains(bodyLower, []byte(`http-equiv='refresh'`))
}

// findSourcesSinks identifies DOM XSS sources/sinks in content.
func (d *Detector) findSourcesSinks(body []byte) []string {
	matches := d.sourcesSinksRE.FindAllString(string(body), -1)

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

// isRedirectCode checks if status code is a redirect (300-310).
func isRedirectCode(code int) bool {
	return code >= 300 && code <= 310
}

// isErrorCode checks if status code is a client error (400-410).
func isErrorCode(code int) bool {
	return code >= 400 && code <= 410
}
