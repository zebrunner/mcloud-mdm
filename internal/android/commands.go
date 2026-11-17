package android

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/headwind"
)

// Param is an argument of a command: a key of the JSON payload of its push message.
type Param struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Type: package, packages (comma separated, sent as a list), path (of the shared storage), text, uri,
	// action (an intent action), json (an object), bool ("1" when on), select (Options)
	Type     string   `json:"type"`
	Required bool     `json:"required,omitempty"`
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// Command is a push message of the agent; the agent writes what it did into the device log of Headwind MDM.
type Command struct {
	Name   string  `json:"name"`
	Group  string  `json:"group"`
	Title  string  `json:"title"`
	Hint   string  `json:"hint"`
	Push   string  `json:"push"`
	Params []Param `json:"params,omitempty"`
	Danger bool    `json:"danger,omitempty"`
}

var (
	packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$`)
	actionPattern  = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)
	pushPattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

var (
	pkgParam    = Param{Key: "pkg", Title: "package", Type: "package", Required: true, Default: "com.android.settings"}
	extraParam  = Param{Key: "extra", Title: "extras", Type: "json", Hint: `{"key": "value", "n": 1, "on": true}: strings, integers and booleans`}
	dataParam   = Param{Key: "data", Title: "data URI", Type: "uri", Hint: "e.g. https://example.com or package:com.example"}
	pathParam   = Param{Key: "path", Title: "path", Type: "path", Required: true, Hint: "relative to the shared storage (/sdcard), e.g. Download/report.txt"}
	actionParam = Param{Key: "action", Title: "action", Type: "action", Required: true}
)

// Commands are every push message of the agent (hmdm-android 6.40 with the patch of android/agent).
var Commands = []*Command{
	{Name: "sync", Group: "Device", Title: "Sync the configuration", Push: "configUpdated",
		Hint: "The agent loads its configuration now: the presets apply, the device info (model, battery, ...) is reported. " +
			"Headwind MDM sends it by itself after a preset change."},
	{Name: "reboot", Group: "Device", Title: "Reboot", Push: "reboot", Danger: true,
		Hint: "DevicePolicyManager.reboot: the device restarts, adb and the session of MCloud drop for a minute. " +
			"Refused during a phone call."},
	{Name: "run-command", Group: "Device", Title: "Run a shell command", Push: "runCommand", Danger: true,
		Params: []Param{{Key: "command", Title: "command", Type: "text", Required: true, Default: "id; getprop ro.build.version.release",
			Hint: "sh -c <command> as the app of the agent (its uid, not the adb shell: no pm, am, settings put of the system)"}},
		Hint: "Runs sh -c as the agent and writes the output (3000 characters at most) into the device log. The agent is an " +
			"app: what an app may do in a shell only (getprop, ls of its own files, ping); adb shell commands are not available."},
	{Name: "run-app", Group: "Apps", Title: "Run an app", Push: "runApp",
		Params: []Param{pkgParam, {Key: "action", Title: "action", Type: "action", Hint: "optional, replaces the action of the launcher intent"}, dataParam, extraParam},
		Hint:   "Starts the launcher activity of the package (like a tap on its icon), with an optional action, data and extras."},
	{Name: "clear-app-data", Group: "Apps", Title: "Clear the data of an app", Push: "clearAppData", Danger: true,
		Params: []Param{pkgParam},
		Hint:   "DevicePolicyManager.clearApplicationUserData (Android 9+): like adb shell pm clear, without adb; the result is in the device log."},
	{Name: "uninstall-app", Group: "Apps", Title: "Uninstall an app", Push: "uninstallApp", Danger: true,
		Params: []Param{pkgParam},
		Hint:   "Silent uninstall by the device owner, no prompt. System apps cannot be uninstalled."},
	{Name: "grant-permissions", Group: "Apps", Title: "Grant the runtime permissions of apps", Push: "grantPermissions",
		Params: []Param{{Key: "pkg", Title: "packages", Type: "packages", Required: true, Default: "com.android.chrome",
			Hint: "comma separated"}, {Key: "mode", Title: "mode", Type: "select", Options: []string{"grant", "default"}}},
		Hint: "grant: every runtime permission the app requests (camera, location, ...) is granted by the device policy, the " +
			"user and the tests cannot revoke it. default: the permissions go back to the user (their state stays). Like adb install -g, after the install."},
	{Name: "intent", Group: "Intents", Title: "Open a screen (activity intent)", Push: "intent",
		Params: []Param{{Key: "action", Title: "action", Type: "action", Required: true, Default: "android.settings.WIFI_SETTINGS",
			Hint: "e.g. android.settings.SETTINGS, android.settings.DATE_SETTINGS, android.intent.action.VIEW (with data)"}, dataParam, extraParam},
		Hint: "Starts an activity by its action (a new task): a settings screen, a URL in the browser (android.intent.action.VIEW + data)."},
	{Name: "broadcast", Group: "Intents", Title: "Send a broadcast", Push: "broadcast",
		Params: []Param{actionParam, {Key: "pkg", Title: "package", Type: "package", Hint: "optional: only this app receives it"}, dataParam, extraParam},
		Hint:   "Sends a broadcast intent as the agent: a test helper app may react to it. Protected system broadcasts are refused by Android."},
	{Name: "delete-file", Group: "Files", Title: "Delete a file", Push: "deleteFile", Danger: true,
		Params: []Param{pathParam},
		Hint:   "Deletes a file of the shared storage (/sdcard/<path>)."},
	{Name: "delete-dir", Group: "Files", Title: "Delete a directory", Push: "deleteDir", Danger: true,
		Params: []Param{pathParam},
		Hint:   "Deletes a directory of the shared storage with its content (/sdcard/<path>)."},
	{Name: "purge-dir", Group: "Files", Title: "Empty a directory", Push: "purgeDir", Danger: true,
		Params: []Param{pathParam, {Key: "recursive", Title: "with the subdirectories", Type: "bool"}},
		Hint:   "Deletes the files of a directory of the shared storage, the subdirectories too when checked; the directory stays."},
	{Name: "clear-downloads", Group: "Files", Title: "Clear the downloads of the agent", Push: "clearDownloadHistory",
		Hint: "Deletes the files the agent downloaded (APKs, files of the configuration) and their history."},
	{Name: "exit-kiosk", Group: "Kiosk", Title: "Exit the kiosk mode", Push: "exitKiosk",
		Hint: "Leaves the kiosk mode until the next configuration. The farm configuration has no kiosk: the agent logs " +
			"\"Exit kiosk by admin command\" and nothing changes on the screen."},
	{Name: "permissive-mode", Group: "Kiosk", Title: "Permissive mode", Push: "permissiveMode",
		Hint: "Stops the agent from hiding the apps outside of the configuration. The farm configuration is permissive already: " +
			"no effect (the agent logs only that it got it)."},
	{Name: "admin-panel", Group: "Kiosk", Title: "Open the admin screen of the agent", Push: "adminPanel", Danger: true,
		Hint: "Opens the admin screen of the agent on the device WITHOUT its password (checked on Android 12): whoever sees " +
			"the screen (the session of MCloud) can change the server and the device ID, clear the restrictions, reset the " +
			"permissions. Close it with Back. adb cannot open it (the activity is not exported)."},
	{Name: "release", Group: "MDM", Title: "Release the device (remove MDM)", Push: releasePush, Danger: true,
		Hint: "The agent gives up the device owner: every restriction goes away, no factory reset. The agent stays " +
			"as a regular app (adb uninstall " + AgentPackage + "); Delete removes the device from the server. " +
			"Without the server: android/release.sh on the host of the device (the secret of the server is the token). " +
			"adb alone cannot remove the device owner."},
	{Name: "raw", Group: "MDM", Title: "Any push message", Push: "",
		Params: []Param{{Key: "type", Title: "message type", Type: "text", Required: true, Default: "configUpdated"},
			{Key: "payload", Title: "payload", Type: "json"}},
		Hint: "A push message of any type with a JSON payload: the types above, the ones of the plugins of the agent " +
			"(com.hmdm.push.<type> broadcasts to the apps)."},
}

// command is the command of the name, nil if there is none.
func command(name string) *Command {
	for _, c := range Commands {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Sent is a command sent to a device.
type Sent struct {
	At      string `json:"at"`
	Serial  string `json:"serial"`
	Name    string `json:"name"`
	Push    string `json:"push"`
	Payload string `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

func validPath(p string) bool {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" || strings.ContainsAny(p, "\x00\n") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// payload builds the JSON payload of the command from the arguments of the UI
func (c *Command) payload(args map[string]string) (string, string, error) {
	push := c.Push
	out := map[string]any{}
	for _, p := range c.Params {
		v := strings.TrimSpace(args[p.Key])
		if v == "" {
			if p.Required {
				return "", "", fmt.Errorf("%s is required", p.Title)
			}
			continue
		}
		switch p.Type {
		case "package":
			if !packagePattern.MatchString(v) {
				return "", "", fmt.Errorf("invalid package %q", v)
			}
			if v == AgentPackage && c.Push != "runApp" && c.Push != "broadcast" {
				return "", "", errors.New("the agent itself: use Release")
			}
			out[p.Key] = v
		case "packages":
			var list []string
			for _, x := range strings.Split(v, ",") {
				if x = strings.TrimSpace(x); x == "" {
					continue
				}
				if !packagePattern.MatchString(x) {
					return "", "", fmt.Errorf("invalid package %q", x)
				}
				list = append(list, x)
			}
			if len(list) == 0 {
				return "", "", fmt.Errorf("%s is required", p.Title)
			}
			out[p.Key] = list
		case "path":
			if !validPath(v) {
				return "", "", fmt.Errorf("invalid path %q: relative to the shared storage, no ..", v)
			}
			out[p.Key] = strings.Trim(v, "/")
		case "action":
			if !actionPattern.MatchString(v) {
				return "", "", fmt.Errorf("invalid action %q", v)
			}
			out[p.Key] = v
		case "bool":
			if v == "1" || v == "true" {
				out[p.Key] = "1"
			}
		case "select":
			found := false
			for _, o := range p.Options {
				found = found || o == v
			}
			if !found {
				return "", "", fmt.Errorf("%s: one of %s", p.Title, strings.Join(p.Options, ", "))
			}
			out[p.Key] = v
		case "json":
			var obj map[string]any
			if err := json.Unmarshal([]byte(v), &obj); err != nil {
				return "", "", fmt.Errorf("%s: a JSON object: %w", p.Title, err)
			}
			out[p.Key] = obj
		default:
			if strings.ContainsRune(v, 0) {
				return "", "", fmt.Errorf("invalid %s", p.Title)
			}
			out[p.Key] = v
		}
	}
	// any push message: its type and payload are the arguments
	if c.Name == "raw" {
		push, _ = out["type"].(string)
		if !pushPattern.MatchString(push) {
			return "", "", fmt.Errorf("invalid message type %q", push)
		}
		if push == releasePush {
			return "", "", errors.New("use the command Release")
		}
		if obj, ok := out["payload"]; ok {
			data, _ := json.Marshal(obj)
			return push, string(data), nil
		}
		return push, "", nil
	}
	if len(out) == 0 {
		return push, "", nil
	}
	data, err := json.Marshal(out)
	return push, string(data), err
}

// Send sends the command with its arguments to the agent of the device.
func (m *Manager) Send(serial, name string, args map[string]string) error {
	c := command(name)
	if c == nil {
		return fmt.Errorf("no command %q", name)
	}
	push, payload, err := c.payload(args)
	if err != nil {
		return err
	}
	dev, err := m.HW.Device(serial)
	if err != nil {
		return err
	}
	if dev == nil {
		return fmt.Errorf("%s is not an Android device of the server", serial)
	}
	err = m.HW.Push(serial, push, payload)
	sent := Sent{At: m.now().UTC().Format(time.RFC3339), Serial: serial, Name: name, Push: push, Payload: payload}
	if err != nil {
		sent.Error = err.Error()
	}
	m.mu.Lock()
	m.history = append([]Sent{sent}, m.history...)
	if len(m.history) > 300 {
		m.history = m.history[:300]
	}
	m.mu.Unlock()
	return err
}

// History are the commands sent, the newest first.
func (m *Manager) History() []Sent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sent{}, m.history...)
}

// Log is the device log of the agent (the newest first): what it did with the commands and the configuration.
func (m *Manager) Log(serial string, limit int) ([]headwind.LogRecord, error) {
	if !ValidSerial(serial) {
		return nil, fmt.Errorf("invalid serial %q", serial)
	}
	return m.HW.DeviceLog(serial, limit)
}
