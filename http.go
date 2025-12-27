package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// NewHTTPClient creates a new HTTP client with connection pooling and proxy support
func NewHTTPClient(config *Config) (*HTTPClient, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Like Python's verify=False
		},
	}

	// Configure proxy if provided
	if config.UseProxy && config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		// Don't follow redirects - like Python's allow_redirects=False
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &HTTPClient{
		client:     client,
		userAgents: UserAgents,
		proxyURL:   config.ProxyURL,
	}, nil
}

// Get performs an HTTP GET request with random User-Agent
func (c *HTTPClient) Get(targetURL string, params map[string]string) (*http.Response, []byte, error) {
	// Build URL with parameters
	finalURL, err := buildRequestURL(targetURL, params)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, nil, err
	}

	// Set random User-Agent
	req.Header.Set("User-Agent", c.randomUserAgent())

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	// Read body
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, nil, err
	}

	return resp, body, nil
}

// GetWithContext performs an HTTP GET request with context support
func (c *HTTPClient) GetWithContext(targetURL string, params map[string]string) (*http.Response, []byte, error) {
	return c.Get(targetURL, params)
}

// randomUserAgent returns a random User-Agent string
func (c *HTTPClient) randomUserAgent() string {
	if len(c.userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	return c.userAgents[rand.Intn(len(c.userAgents))]
}

// buildRequestURL constructs URL with query parameters
func buildRequestURL(baseURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return baseURL, nil
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Get existing query parameters
	query := parsedURL.Query()

	// Add/replace with new parameters
	for key, value := range params {
		query.Set(key, value)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

// EnsureScheme adds http:// if URL has no scheme
func EnsureScheme(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return "http://" + rawURL
	}
	return rawURL
}

func init() {
	// Seed random for User-Agent rotation
	rand.Seed(time.Now().UnixNano())
}
