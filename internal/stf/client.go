// Package stf reads the devices of STF (MCloud): their names, nodes and locations for the groups of the admin UI, and
// whether a user uses one (the jobs that wait for free devices). Read only, with an access token of STF.
package stf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Device is a device of STF: the serial is the udid of an iOS device and the adb serial of an Android one.
type Device struct {
	Serial string `json:"serial"`
	Name   string `json:"name,omitempty"`
	// Node is the host of the device, Location the location of mcloud-agent (the provider is <agent>_<location>)
	Node     string `json:"node,omitempty"`
	Location string `json:"location,omitempty"`
	Provider string `json:"provider,omitempty"`
	Present  bool   `json:"present"`
	Ready    bool   `json:"ready"`
	// Busy: a user (or a test session) has the device; Owner is the user
	Busy  bool   `json:"busy"`
	Owner string `json:"owner,omitempty"`
}

// Client is the API of STF; a nil Client knows no device.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
	// TTL of the cached list
	TTL time.Duration

	mu      sync.Mutex
	at      time.Time
	devices map[string]Device
	err     error
}

// New returns a client of the API of STF at url (http://stf-api:3000).
func New(url, token string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), Token: token, HTTP: &http.Client{Timeout: 10 * time.Second}, TTL: 10 * time.Second}
}

type apiDevice struct {
	Serial   string `json:"serial"`
	Name     string `json:"name"`
	Node     string `json:"node"`
	Present  bool   `json:"present"`
	Ready    bool   `json:"ready"`
	Using    bool   `json:"using"`
	Provider *struct {
		Name string `json:"name"`
	} `json:"provider"`
	Owner *struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"owner"`
}

// Devices are the devices of STF by serial, cached for TTL.
func (c *Client) Devices() (map[string]Device, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < c.TTL {
		return c.devices, c.err
	}
	c.devices, c.err = c.fetch()
	c.at = time.Now()
	return c.devices, c.err
}

func (c *Client) fetch() (map[string]Device, error) {
	req, err := http.NewRequest(http.MethodGet, c.URL+"/api/v1/devices?fields=serial,name,node,present,ready,using,owner,provider", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STF: %d %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	var data struct {
		Devices []apiDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("STF: %w", err)
	}
	out := map[string]Device{}
	for _, d := range data.Devices {
		v := Device{Serial: d.Serial, Name: d.Name, Node: d.Node, Present: d.Present, Ready: d.Ready, Busy: d.Using}
		if d.Provider != nil {
			v.Provider = d.Provider.Name
			if _, location, ok := strings.Cut(d.Provider.Name, "_"); ok {
				v.Location = location
			}
		}
		if d.Owner != nil && (d.Owner.Email != "" || d.Owner.Name != "") {
			v.Busy, v.Owner = true, d.Owner.Email
			if v.Owner == "" {
				v.Owner = d.Owner.Name
			}
		}
		out[d.Serial] = v
	}
	return out, nil
}
