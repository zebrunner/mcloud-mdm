// Package headwind is the client of the REST API of Headwind MDM, the server of the Android agents.
package headwind

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client logs in with the login and the password of a user of Headwind MDM and keeps its JWT.
type Client struct {
	URL      string
	Login    string
	Password string
	HTTP     *http.Client

	mu    sync.Mutex
	token string
}

// New returns a client with a timeout.
func New(base, login, password string) *Client {
	return &Client{URL: strings.TrimRight(base, "/"), Login: login, Password: password,
		HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Device is a device of Headwind MDM; Number is the device ID of the agent (the adb serial in MCloud).
type Device struct {
	ID              int         `json:"id,omitempty"`
	Number          string      `json:"number"`
	Description     string      `json:"description,omitempty"`
	ConfigurationID int         `json:"configurationId"`
	LastUpdate      int64       `json:"lastUpdate,omitempty"`
	StatusCode      string      `json:"statusCode,omitempty"`
	LauncherVersion string      `json:"launcherVersion,omitempty"`
	Info            *DeviceInfo `json:"info,omitempty"`
}

// DeviceInfo is what the agent reports on every synchronization.
type DeviceInfo struct {
	Model           string `json:"model,omitempty"`
	AndroidVersion  string `json:"androidVersion,omitempty"`
	BatteryLevel    int    `json:"batteryLevel,omitempty"`
	MdmMode         bool   `json:"mdmMode"`
	KioskMode       bool   `json:"kioskMode"`
	DefaultLauncher bool   `json:"defaultLauncher"`
}

// Config is a configuration of Headwind MDM as it is: many fields, mcloud-mdm sets its own ones by key.
type Config map[string]any

// ID is the id of the configuration, 0 if it has none.
func (c Config) ID() int {
	if v, ok := c["id"].(float64); ok {
		return int(v)
	}
	return 0
}

// Name is the name of the configuration.
func (c Config) Name() string {
	v, _ := c["name"].(string)
	return v
}

// APIError is an answer of Headwind MDM other than OK.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Headwind MDM: %d %s", e.Status, e.Message)
}

// PasswordHash is what the web panel of Headwind MDM sends: the MD5 of the password, upper case hex.
func PasswordHash(password string) string {
	sum := md5.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (c *Client) login() (string, error) {
	body, _ := json.Marshal(map[string]string{"login": c.Login, "password": PasswordHash(c.Password)})
	resp, err := c.HTTP.Post(c.URL+"/rest/public/jwt/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{Status: resp.StatusCode, Message: "the login of " + c.Login + " is refused"}
	}
	var r struct {
		Token string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil || r.Token == "" {
		return "", errors.New("Headwind MDM: no token in the answer of the login")
	}
	return r.Token, nil
}

// call sends a request of the private API and decodes the data of its {status, message, data} answer into out;
// a refused token is renewed once (a user with a pending password reset is refused too: 403)
func (c *Client) call(method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		c.mu.Lock()
		if c.token == "" {
			token, err := c.login()
			if err != nil {
				c.mu.Unlock()
				return err
			}
			c.token = token
		}
		token := c.token
		c.mu.Unlock()

		req, err := http.NewRequest(method, c.URL+"/rest/private"+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			c.mu.Lock()
			if c.token == token {
				c.token = ""
			}
			c.mu.Unlock()
			if attempt == 0 {
				continue
			}
		}
		if resp.StatusCode != http.StatusOK {
			return &APIError{Status: resp.StatusCode, Message: method + " " + path}
		}
		var r struct {
			Status  string          `json:"status"`
			Message *string         `json:"message"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("Headwind MDM: %s %s: %w", method, path, err)
		}
		if r.Status != "OK" {
			msg := r.Status
			if r.Message != nil {
				msg += ": " + *r.Message
			}
			return &APIError{Status: resp.StatusCode, Message: msg}
		}
		if out != nil && len(r.Data) > 0 && string(r.Data) != "null" {
			return json.Unmarshal(r.Data, out)
		}
		return nil
	}
}

// Devices are all the devices.
func (c *Client) Devices() ([]Device, error) {
	var r struct {
		Devices struct {
			Items []Device `json:"items"`
		} `json:"devices"`
	}
	err := c.call(http.MethodPost, "/devices/search", map[string]int{"pageSize": 100000, "pageNum": 1}, &r)
	return r.Devices.Items, err
}

// Device is the device of the number, nil if there is none.
func (c *Client) Device(number string) (*Device, error) {
	list, err := c.Devices()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Number == number {
			return &list[i], nil
		}
	}
	return nil, nil
}

// SaveDevice creates the device (no ID) or updates it.
func (c *Client) SaveDevice(d Device) error {
	return c.call(http.MethodPut, "/devices", d, nil)
}

// DeleteDevice removes the device from the server.
func (c *Client) DeleteDevice(id int) error {
	return c.call(http.MethodDelete, fmt.Sprintf("/devices/%d", id), nil, nil)
}

// Configurations are all the configurations with their settings, without their applications.
func (c *Client) Configurations() ([]Config, error) {
	var list []Config
	err := c.call(http.MethodGet, "/configurations/search", nil, &list)
	return list, err
}

// Configuration is the configuration with its applications: the ones it has, not every known one.
func (c *Client) Configuration(id int) (Config, error) {
	var cfg Config
	if err := c.call(http.MethodGet, fmt.Sprintf("/configurations/%d", id), nil, &cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("Headwind MDM: no configuration %d", id)
	}
	var apps []map[string]any
	if err := c.call(http.MethodGet, fmt.Sprintf("/configurations/applications/%d", id), nil, &apps); err != nil {
		return nil, err
	}
	selected := []map[string]any{}
	for _, a := range apps {
		if on, _ := a["selected"].(bool); on {
			selected = append(selected, a)
		}
	}
	cfg["applications"] = selected
	return cfg, nil
}

// SaveConfiguration updates the configuration with its applications; Headwind MDM tells its devices by push.
func (c *Client) SaveConfiguration(cfg Config) error {
	return c.call(http.MethodPut, "/configurations", cfg, nil)
}

// CopyConfiguration copies the configuration with its applications under a new name and returns the copy.
func (c *Client) CopyConfiguration(from int, name, description string) (Config, error) {
	if err := c.call(http.MethodPut, "/configurations/copy",
		map[string]any{"id": from, "name": name, "description": description}, nil); err != nil {
		return nil, err
	}
	list, err := c.Configurations()
	if err != nil {
		return nil, err
	}
	for _, cfg := range list {
		if cfg.Name() == name {
			return c.Configuration(cfg.ID())
		}
	}
	return nil, fmt.Errorf("Headwind MDM: the copy %q is missing", name)
}

// DeleteConfiguration removes the configuration (no device may use it).
func (c *Client) DeleteConfiguration(id int) error {
	return c.call(http.MethodDelete, fmt.Sprintf("/configurations/%d", id), nil, nil)
}

// Push sends a push message (MQTT) to the agent of the device; payload is JSON or empty.
func (c *Client) Push(number, messageType, payload string) error {
	msg := map[string]any{"messageType": messageType, "deviceNumbers": []string{number}}
	// Headwind MDM writes the payload into the MQTT message as it is: an empty one breaks the JSON of the agent
	if payload != "" {
		msg["payload"] = payload
	}
	return c.call(http.MethodPost, "/push", msg, nil)
}

// Ping checks the login: a pending password reset of the user is reported.
func (c *Client) Ping() error {
	_, err := c.Configurations()
	return err
}
