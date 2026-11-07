package httpengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const MaxResponseBytes = 50 * 1024 * 1024 // 50 MB memory-safe cap

// HeaderKV represents an individual HTTP header entry.
type HeaderKV struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
}

// AuthConfig represents HTTP authentication configuration.
type AuthConfig struct {
	Type     string `json:"type"`     // "none", "bearer", "basic", "apikey"
	Token    string `json:"token"`    // for bearer
	Username string `json:"username"` // for basic
	Password string `json:"password"` // for basic
	APIKey   string `json:"apiKey"`   // key name for apikey
	APIValue string `json:"apiValue"` // value for apikey
	APIIn    string `json:"apiIn"`    // "header" or "query"
}

// ResponseResult holds the outcome of an HTTP execution.
type ResponseResult struct {
	StatusCode int               `json:"status_code"`
	StatusText string            `json:"status_text"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Duration   int64             `json:"duration"`
	SizeBytes  int64             `json:"size_bytes"`
	Error      string            `json:"error,omitempty"`
}

// Engine executes HTTP requests with per-request cancellation and variable interpolation.
type Engine struct {
	client   *http.Client
	mu       sync.Mutex
	inFlight map[string]context.CancelFunc
}

var varRegex = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}`)

// NewEngine creates a new HTTP execution engine.
func NewEngine() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		inFlight: make(map[string]context.CancelFunc),
	}
}

// Interpolate recursively resolves {{var}} placeholders up to 5 levels deep.
func Interpolate(input string, vars map[string]string) string {
	if len(vars) == 0 || input == "" {
		return input
	}
	res := input
	for range 5 {
		changed := false
		res = varRegex.ReplaceAllStringFunc(res, func(match string) string {
			sub := varRegex.FindStringSubmatch(match)
			if len(sub) > 1 {
				if val, ok := vars[sub[1]]; ok {
					changed = true
					return val
				}
			}
			return match
		})
		if !changed {
			break
		}
	}
	return res
}

// CancelRequest aborts an in-flight HTTP request by its requestID.
func (e *Engine) CancelRequest(requestID string) {
	e.mu.Lock()
	cancel, ok := e.inFlight[requestID]
	if ok {
		delete(e.inFlight, requestID)
	}
	e.mu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

// Execute performs an HTTP call with variable substitution, auth, and cancellation support.
func (e *Engine) Execute(requestID, method, rawURL, headersJSON, body, authJSON string, vars map[string]string) (*ResponseResult, error) {
	ctx, cancel := context.WithCancel(context.Background())
	if requestID != "" {
		e.mu.Lock()
		if prev, exists := e.inFlight[requestID]; exists {
			prev()
		}
		e.inFlight[requestID] = cancel
		e.mu.Unlock()
		defer func() {
			e.mu.Lock()
			delete(e.inFlight, requestID)
			e.mu.Unlock()
			cancel()
		}()
	} else {
		defer cancel()
	}

	resolvedURL := strings.TrimSpace(Interpolate(rawURL, vars))
	if !strings.HasPrefix(resolvedURL, "http://") && !strings.HasPrefix(resolvedURL, "https://") {
		resolvedURL = "https://" + resolvedURL
	}
	resolvedBody := Interpolate(body, vars)

	var authCfg AuthConfig
	if authJSON != "" {
		_ = json.Unmarshal([]byte(authJSON), &authCfg)
	}

	if strings.EqualFold(authCfg.Type, "apikey") && strings.EqualFold(authCfg.APIIn, "query") {
		k := Interpolate(authCfg.APIKey, vars)
		v := Interpolate(authCfg.APIValue, vars)
		if k != "" {
			if u, err := url.Parse(resolvedURL); err == nil {
				q := u.Query()
				q.Set(k, v)
				u.RawQuery = q.Encode()
				resolvedURL = u.String()
			}
		}
	}

	var bodyReader io.Reader
	if resolvedBody != "" && method != http.MethodGet && method != http.MethodHead {
		bodyReader = bytes.NewBufferString(resolvedBody)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), resolvedURL, bodyReader)
	if err != nil {
		return &ResponseResult{Error: err.Error()}, nil
	}

	var headers []HeaderKV
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &headers)
	}
	for _, h := range headers {
		if h.Enabled && strings.TrimSpace(h.Key) != "" {
			req.Header.Set(Interpolate(h.Key, vars), Interpolate(h.Value, vars))
		}
	}

	switch strings.ToLower(authCfg.Type) {
	case "bearer":
		tok := Interpolate(authCfg.Token, vars)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	case "basic":
		u := Interpolate(authCfg.Username, vars)
		p := Interpolate(authCfg.Password, vars)
		if u != "" || p != "" {
			req.SetBasicAuth(u, p)
		}
	case "apikey":
		if !strings.EqualFold(authCfg.APIIn, "query") {
			k := Interpolate(authCfg.APIKey, vars)
			v := Interpolate(authCfg.APIValue, vars)
			if k != "" {
				req.Header.Set(k, v)
			}
		}
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return &ResponseResult{
			Duration: dur,
			Error:    err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, MaxResponseBytes)
	respBytes, err := io.ReadAll(limited)
	if err != nil {
		return &ResponseResult{
			StatusCode: resp.StatusCode,
			StatusText: resp.Status,
			Duration:   dur,
			Error:      fmt.Sprintf("read body: %v", err),
		}, nil
	}

	respHeaders := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		respHeaders[k] = strings.Join(vals, ", ")
	}

	return &ResponseResult{
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Headers:    respHeaders,
		Body:       string(respBytes),
		Duration:   dur,
		SizeBytes:  int64(len(respBytes)),
	}, nil
}
