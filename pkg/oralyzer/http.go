package oralyzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// DefaultRetryDelays defines the default retry intervals for 429/503 responses.
var DefaultRetryDelays = []time.Duration{
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// newHTTPClient creates a new HTTP client with connection pooling and proxy support.
func newHTTPClient(config *Config) (*httpClient, error) {
	insecureSkipVerify := true
	if config != nil {
		insecureSkipVerify = config.InsecureSkipVerify
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	}

	// Configure proxy if provided
	if config != nil && config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	timeout := 10 * time.Second
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if config != nil && config.FollowRedirects {
		checkRedirect = nil
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}

	proxyURL := ""
	headers := make(map[string]string)
	retryEnabled := false

	if config != nil {
		proxyURL = config.ProxyURL
		if config.Headers != nil {
			headers = config.Headers
		}
		retryEnabled = config.RetryEnabled
	}

	return &httpClient{
		client:       client,
		userAgents:   UserAgents,
		proxyURL:     proxyURL,
		headers:      headers,
		retryEnabled: retryEnabled,
		retryDelays:  DefaultRetryDelays,
	}, nil
}

// Get performs an HTTP GET request with random User-Agent and retry support.
func (c *httpClient) Get(targetURL string, params map[string]string) (*http.Response, []byte, error) {
	finalURL, err := buildRequestURL(targetURL, params)
	if err != nil {
		return nil, nil, err
	}

	var resp *http.Response
	var body []byte
	var lastErr error

	// Try initial request + retries
	maxAttempts := 1
	if c.retryEnabled {
		maxAttempts = len(c.retryDelays) + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Wait before retry (skip first attempt)
		if attempt > 0 && c.retryEnabled {
			time.Sleep(c.retryDelays[attempt-1])
		}

		req, err := http.NewRequest("GET", finalURL, nil)
		if err != nil {
			return nil, nil, err
		}

		// Set User-Agent
		req.Header.Set("User-Agent", c.randomUserAgent())

		// Set custom headers
		for key, value := range c.headers {
			req.Header.Set(key, value)
		}

		resp, err = c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if we need to retry (429 Too Many Requests, 503 Service Unavailable)
		if c.retryEnabled && (resp.StatusCode == 429 || resp.StatusCode == 503) {
			resp.Body.Close()
			if attempt < len(c.retryDelays) {
				continue // Retry
			}
		}

		// Read body
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return resp, nil, err
		}

		return resp, body, nil
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}

	return resp, body, nil
}

// randomUserAgent returns a random User-Agent string.
func (c *httpClient) randomUserAgent() string {
	if len(c.userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	return c.userAgents[rand.Intn(len(c.userAgents))]
}

// buildRequestURL constructs URL with query parameters.
func buildRequestURL(baseURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return baseURL, nil
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

// EnsureScheme adds http:// if URL has no scheme.
func EnsureScheme(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return "http://" + rawURL
	}
	return rawURL
}
