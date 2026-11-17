// Package nanohub is the client of the API of NanoHUB and the encoding of the MDM commands.
package nanohub

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"howett.net/plist"
)

// Client talks to NanoHUB with its API key (HTTP Basic, user nanohub).
type Client struct {
	URL  string
	Key  string
	HTTP *http.Client
}

// New returns a client with a timeout.
func New(base, key string) *Client {
	return &Client{URL: strings.TrimRight(base, "/"), Key: key, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Do sends a request to path (/api/v1/... or /version) and returns the status and the body.
func (c *Client) Do(method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth("nanohub", c.Key)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, data, err
}

// Enqueue puts the command into the queue of the device and pushes it.
func (c *Client) Enqueue(udid string, command []byte) (int, []byte, error) {
	return c.Do(http.MethodPut, "/api/v1/nanomdm/enqueue/"+url.PathEscape(udid), command)
}

// Push sends an APNs push only: the device connects and takes its queue.
func (c *Client) Push(udid string) (int, []byte, error) {
	return c.Do(http.MethodGet, "/api/v1/nanomdm/push/"+url.PathEscape(udid), nil)
}

// NotifyDDM makes the device synchronize its declarations (KMFDDM of NanoHUB).
func (c *Client) NotifyDDM(udid string) (int, []byte, error) {
	return c.Do(http.MethodPost, "/api/v1/ddm/notify?id="+url.QueryEscape(udid), nil)
}

// PushCert uploads the push certificate with its key (PEM) and returns the topic and the expiry NanoHUB reports.
func (c *Client) PushCert(pemData []byte) (topic string, notAfter string, err error) {
	status, body, err := c.Do(http.MethodPut, "/api/v1/nanomdm/pushcert", pemData)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", fmt.Errorf("NanoHUB: %d %s", status, strings.TrimSpace(string(body)))
	}
	var r struct {
		Topic    string `json:"topic"`
		NotAfter string `json:"not_after"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Topic == "" {
		return "", "", fmt.Errorf("NanoHUB: no topic in %q", body)
	}
	return r.Topic, r.NotAfter, nil
}

// NewCommand returns the plist of a command with a new CommandUUID; args come from JSON, {"$data": "<base64>"}
// is data.
func NewCommand(requestType string, args map[string]any) (string, []byte, error) {
	command := map[string]any{}
	for k, v := range args {
		value, err := toPlist(v)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", k, err)
		}
		command[k] = value
	}
	command["RequestType"] = requestType
	id := NewUUID()
	data, err := plist.Marshal(map[string]any{"CommandUUID": id, "Command": command}, plist.XMLFormat)
	return id, data, err
}

func toPlist(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		if d, ok := t["$data"]; ok && len(t) == 1 {
			s, _ := d.(string)
			return base64.StdEncoding.DecodeString(s)
		}
		out := map[string]any{}
		for k, item := range t {
			value, err := toPlist(item)
			if err != nil {
				return nil, err
			}
			out[k] = value
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			value, err := toPlist(item)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case float64:
		// JSON numbers: whole ones are the integers of plist
		if t == float64(int64(t)) {
			return int64(t), nil
		}
		return t, nil
	default:
		return v, nil
	}
}

// NewUUID returns a random upper case UUID (the CommandUUID of the commands).
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
