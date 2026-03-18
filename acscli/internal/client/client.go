package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client is an HTTP client for the StackRox API
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	username   string
	password   string
}

// Config holds client configuration
type Config struct {
	Endpoint string
	Token    string
	Username string
	Password string
	Insecure bool
	Timeout  time.Duration
}

// NewClient creates a new API client
func NewClient(cfg Config) (*Client, error) {
	// Get endpoint from config, env, or default
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("ROX_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "localhost:8443"
	}

	// Normalize endpoint to URL
	baseURL := endpoint
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Get auth from config or env
	token := cfg.Token
	if token == "" {
		token = os.Getenv("ROX_API_TOKEN")
	}

	username := cfg.Username
	password := cfg.Password
	if password == "" {
		password = os.Getenv("ROX_ADMIN_PASSWORD")
	}
	if username == "" && password != "" {
		username = "admin"
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
		},
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		token:    token,
		username: username,
		password: password,
	}, nil
}

// Request makes an HTTP request to the API
func (c *Client) Request(method, path string, body interface{}) ([]byte, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "acs-cli/1.0")

	// Set auth
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// Get makes a GET request
func (c *Client) Get(path string) ([]byte, error) {
	return c.Request("GET", path, nil)
}

// Post makes a POST request
func (c *Client) Post(path string, body interface{}) ([]byte, error) {
	return c.Request("POST", path, body)
}

// Put makes a PUT request
func (c *Client) Put(path string, body interface{}) ([]byte, error) {
	return c.Request("PUT", path, body)
}

// Delete makes a DELETE request
func (c *Client) Delete(path string) ([]byte, error) {
	return c.Request("DELETE", path, nil)
}

// APIError represents an API error response
type APIError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Status)
}

// MarshalJSON implements json.Marshaler for structured error output
func (e *APIError) MarshalJSON() ([]byte, error) {
	// Try to parse body as JSON
	var bodyJSON interface{}
	if err := json.Unmarshal([]byte(e.Body), &bodyJSON); err != nil {
		bodyJSON = e.Body
	}

	return json.Marshal(map[string]interface{}{
		"error":       true,
		"status_code": e.StatusCode,
		"status":      e.Status,
		"details":     bodyJSON,
	})
}

// ExitCode returns an appropriate exit code for this error
func (e *APIError) ExitCode() int {
	switch e.StatusCode {
	case 401:
		return 3 // Authentication error
	case 403:
		return 5 // Permission denied
	case 404:
		return 4 // Not found
	default:
		return 1 // General API error
	}
}
