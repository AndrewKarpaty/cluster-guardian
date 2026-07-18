// Package prom is a minimal Prometheus HTTP API client — just enough to run
// instant queries for the optimization checks, without pulling in the full
// prometheus client library.
package prom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client talks to a Prometheus server's HTTP API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client for the Prometheus server at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

type apiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Error string `json:"error"`
}

// QueryScalar runs an instant query and returns the sum of all returned
// sample values (queries used here aggregate to a single vector element).
func (c *Client) QueryScalar(ctx context.Context, query string) (float64, error) {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", c.BaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("prometheus returned HTTP %d", resp.StatusCode)
	}
	var body apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decoding response: %w", err)
	}
	if body.Status != "success" {
		return 0, fmt.Errorf("query failed: %s", body.Error)
	}
	var sum float64
	for _, r := range body.Data.Result {
		if s, ok := r.Value[1].(string); ok {
			if v, err := strconv.ParseFloat(s, 64); err == nil {
				sum += v
			}
		}
	}
	if len(body.Data.Result) == 0 {
		return 0, fmt.Errorf("query returned no data")
	}
	return sum, nil
}
