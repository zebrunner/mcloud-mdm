// Package android manages the Android devices through Headwind MDM: the agent of android/agent is the device owner,
// every device has its own configuration "mcloud-<serial>" (its presets), the commands are push messages.
package android

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/headwind"
)

// Agent is the package and the admin receiver of the agent.
const (
	AgentPackage   = "com.hmdm.launcher"
	AgentAdmin     = AgentPackage + "/.AdminReceiver"
	SetupURI       = "content://" + AgentPackage + ".mcloud"
	configPrefix   = "mcloud-"
	releasePush    = "mcloudRelease"
	baseConfigName = "Common - Minimal"
)

// serialPattern: the adb serials (USB) and ip:port of adb over Wi-Fi are not device IDs of the agent
var serialPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{4,64}$`)

// Preset is a policy of the configuration of a device: user restrictions of Android and fields of Headwind MDM.
type Preset struct {
	Name         string         `json:"name"`
	Title        string         `json:"title"`
	Hint         string         `json:"hint"`
	Restrictions []string       `json:"restrictions,omitempty"`
	On           map[string]any `json:"-"`
	Off          map[string]any `json:"-"`
}

// Presets of the Android devices, checked on a Pixel 3 XL (Android 12). DISALLOW_DEBUGGING_FEATURES,
// DISALLOW_INSTALL_APPS and DISALLOW_UNINSTALL_APPS are never offered: they break adb and the farm. The agent always
// sets DISALLOW_SAFE_BOOT itself: safe mode would stop it.
var Presets = []*Preset{
	{
		Name: "swupdate-postpone", Title: "Postpone system updates (30 days)",
		Hint: "SystemUpdatePolicy postpone: Android does not install an OTA update for 30 days after it is found " +
			"(then the user may install it). Security updates of the Play system are not affected.",
		On: map[string]any{"systemUpdateType": 3}, Off: map[string]any{"systemUpdateType": 0},
	},
	{
		Name: "bluetooth-off", Title: "Turn Bluetooth off and lock it",
		Hint: "The agent turns Bluetooth off, DISALLOW_BLUETOOTH (no_bluetooth) locks it: the toggle is gray. " +
			"Removing the preset unlocks it, Bluetooth stays off.",
		Restrictions: []string{"no_bluetooth"},
		On:           map[string]any{"bluetooth": false}, Off: map[string]any{"bluetooth": nil},
	},
	{
		Name: "erase-off", Title: "Forbid factory reset",
		Hint:         "DISALLOW_FACTORY_RESET (no_factory_reset): Settings cannot erase the device. The recovery mode still can.",
		Restrictions: []string{"no_factory_reset"},
	},
	{
		Name: "wifi-locked", Title: "Lock the Wi-Fi networks",
		Hint: "DISALLOW_CONFIG_WIFI (no_config_wifi): the user cannot add, change or forget networks; the device " +
			"stays on the networks it knows.",
		Restrictions: []string{"no_config_wifi"},
	},
	{
		Name: "accounts-off", Title: "Forbid adding accounts",
		Hint: "DISALLOW_MODIFY_ACCOUNTS (no_modify_accounts): no Google or other account can be added or removed. " +
			"Do not use it when tests sign in to Google.",
		Restrictions: []string{"no_modify_accounts"},
	},
	{
		Name: "users-off", Title: "Forbid new users and guests",
		Hint:         "DISALLOW_ADD_USER (no_add_user): no new user or guest; a test cannot leave the device in another user.",
		Restrictions: []string{"no_add_user"},
	},
}

// preset is the preset of the name, nil if there is none.
func preset(name string) *Preset {
	for _, p := range Presets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// Command is a push message of the admin UI.
type Command struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Hint  string `json:"hint"`
	// Push is the message type of the agent; Package marks the commands with a package name argument
	Push    string `json:"-"`
	Package bool   `json:"package"`
	Danger  bool   `json:"danger,omitempty"`
}

// Commands of the Android devices.
var Commands = []*Command{
	{Name: "sync", Title: "Sync the configuration", Push: "configUpdated",
		Hint: "The agent loads its configuration now and reports the device info: the presets apply."},
	{Name: "reboot", Title: "Reboot", Push: "reboot", Danger: true,
		Hint: "DevicePolicyManager.reboot: the device restarts, adb and the session of MCloud drop for a minute."},
	{Name: "run-app", Title: "Run an app", Push: "runApp", Package: true,
		Hint: "Starts the launcher activity of the package, e.g. com.android.settings."},
	{Name: "clear-app-data", Title: "Clear the data of an app", Push: "clearAppData", Package: true, Danger: true,
		Hint: "DevicePolicyManager.clearApplicationUserData (Android 9+): like pm clear, without adb."},
	{Name: "uninstall-app", Title: "Uninstall an app", Push: "uninstallApp", Package: true, Danger: true,
		Hint: "Silent uninstall by the device owner."},
	{Name: "release", Title: "Release the device (remove MDM)", Push: releasePush, Danger: true,
		Hint: "The agent gives up the device owner: every restriction goes away, no factory reset. The agent stays " +
			"as a regular app (adb uninstall " + AgentPackage + "); Delete removes the device from the server. " +
			"Over adb: adb shell dpm remove-active-admin " + AgentAdmin + "."},
}

// Manager is the Android part of mcloud-mdm.
type Manager struct {
	HW *headwind.Client
	// PublicURL is the URL of Headwind MDM the agents reach, Secret its shared secret (SHARED_SECRET)
	PublicURL string
	Secret    string
	Now       func() time.Time

	mu sync.Mutex
	// changed is the time of the last preset change of a device: applied once the device synchronized after it
	changed map[string]time.Time
}

// Setup is what a device host needs to enroll a device over adb.
type Setup struct {
	Serial    string   `json:"serial"`
	BaseURL   string   `json:"base_url"`
	Secret    string   `json:"secret"`
	AgentURL  string   `json:"agent_url,omitempty"`
	ADB       []string `json:"adb"`
	Configure string   `json:"configure"`
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// farm makes a configuration safe for a device farm: the system launcher stays, the agent does not grant
// permissions to the apps nor installs apps of its own, no kiosk
func farm(cfg headwind.Config) {
	cfg["runDefaultLauncher"] = true
	cfg["permissive"] = true
	cfg["appPermissions"] = "ASKALL"
	cfg["kioskMode"] = false
	cfg["pushOptions"] = "mqttWorker"
	cfg["requestUpdates"] = "DONOTTRACK"
	// the password of the local admin screen of the agent: nobody needs it, Headwind MDM requires one
	cfg["password"] = randomHex(8)
	apps, _ := cfg["applications"].([]any)
	if apps == nil {
		if typed, ok := cfg["applications"].([]map[string]any); ok {
			for _, a := range typed {
				apps = append(apps, a)
			}
		}
	}
	kept := []any{}
	for _, a := range apps {
		if am, ok := a.(map[string]any); ok && am["pkg"] == AgentPackage {
			kept = append(kept, am)
		}
	}
	cfg["applications"] = kept
}

// ValidSerial reports a serial the agent can use as its device ID.
func ValidSerial(serial string) bool {
	return serialPattern.MatchString(serial) && !strings.Contains(serial, ":")
}

// Enroll prepares the server for the device: its own configuration and the device; the agent is set up over adb.
func (m *Manager) Enroll(serial, name, agentURL string) (*Setup, error) {
	if !ValidSerial(serial) {
		return nil, fmt.Errorf("invalid serial %q: the adb serial of a USB device", serial)
	}
	cfg, err := m.deviceConfig(serial)
	if err != nil {
		return nil, err
	}
	dev, err := m.HW.Device(serial)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		dev = &headwind.Device{Number: serial}
	}
	dev.ConfigurationID = cfg.ID()
	if name != "" {
		dev.Description = name
	}
	if err := m.HW.SaveDevice(headwind.Device{ID: dev.ID, Number: serial, Description: dev.Description,
		ConfigurationID: dev.ConfigurationID}); err != nil {
		return nil, err
	}
	s := &Setup{Serial: serial, BaseURL: m.PublicURL, Secret: m.Secret, AgentURL: agentURL}
	s.Configure = fmt.Sprintf("content call --uri %s --method setup --arg %s --extra deviceId:s:%s --extra secret:s:%s",
		SetupURI, m.PublicURL, serial, m.Secret)
	s.ADB = []string{
		"adb -s " + serial + " install -t -r mcloud-mdm-agent.apk",
		"adb -s " + serial + " shell dpm set-device-owner " + AgentAdmin,
		"adb -s " + serial + " shell " + s.Configure,
		"adb -s " + serial + " shell am start -n " + AgentPackage + "/.ui.MainActivity",
	}
	return s, nil
}

// deviceConfig is the configuration of the device, created from the base configuration of Headwind MDM
func (m *Manager) deviceConfig(serial string) (headwind.Config, error) {
	list, err := m.HW.Configurations()
	if err != nil {
		return nil, err
	}
	base := 0
	for _, c := range list {
		if c.Name() == configPrefix+serial {
			return m.HW.Configuration(c.ID())
		}
		if c.Name() == baseConfigName || (base == 0 && !strings.HasPrefix(c.Name(), configPrefix)) {
			base = c.ID()
		}
	}
	if base == 0 {
		return nil, errors.New("Headwind MDM has no configuration to copy")
	}
	cfg, err := m.HW.CopyConfiguration(base, configPrefix+serial, "mcloud-mdm: the configuration of "+serial)
	if err != nil {
		return nil, err
	}
	farm(cfg)
	if err := m.HW.SaveConfiguration(cfg); err != nil {
		return nil, err
	}
	return m.HW.Configuration(cfg.ID())
}

// Device is an Android device of the admin UI.
type Device struct {
	Serial      string          `json:"serial"`
	Name        string          `json:"name,omitempty"`
	Model       string          `json:"model,omitempty"`
	OSVersion   string          `json:"os_version,omitempty"`
	Battery     int             `json:"battery,omitempty"`
	Owner       bool            `json:"device_owner"`
	Status      string          `json:"status,omitempty"`
	Agent       string          `json:"agent_version,omitempty"`
	LastSyncAt  string          `json:"last_sync_at,omitempty"`
	Presets     map[string]bool `json:"presets"`
	Pending     bool            `json:"pending"`
	Unmanaged   bool            `json:"unmanaged,omitempty"`
	Restriction string          `json:"restrictions,omitempty"`
}

// Devices are the devices of Headwind MDM with the presets of their configurations.
func (m *Manager) Devices() ([]Device, error) {
	devices, err := m.HW.Devices()
	if err != nil {
		return nil, err
	}
	configs, err := m.HW.Configurations()
	if err != nil {
		return nil, err
	}
	byID := map[int]headwind.Config{}
	for _, c := range configs {
		byID[c.ID()] = c
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for _, d := range devices {
		cfg := byID[d.ConfigurationID]
		v := Device{Serial: d.Number, Name: d.Description, Status: d.StatusCode, Agent: d.LauncherVersion,
			Presets: map[string]bool{}, Unmanaged: cfg == nil || cfg.Name() != configPrefix+d.Number}
		if d.Info != nil {
			v.Model, v.OSVersion, v.Battery, v.Owner = d.Info.Model, d.Info.AndroidVersion, d.Info.BatteryLevel, d.Info.MdmMode
		}
		var synced time.Time
		if d.LastUpdate > 0 {
			synced = time.UnixMilli(d.LastUpdate).UTC()
			v.LastSyncAt = synced.Format(time.RFC3339)
		}
		if cfg != nil {
			for _, p := range Presets {
				v.Presets[p.Name] = presetOn(cfg, p)
			}
			v.Restriction, _ = cfg["restrictions"].(string)
		}
		if at, ok := m.changed[d.Number]; ok {
			v.Pending = synced.Before(at)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	return out, nil
}

func restrictionList(cfg headwind.Config) []string {
	s, _ := cfg["restrictions"].(string)
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

func presetOn(cfg headwind.Config, p *Preset) bool {
	have := restrictionList(cfg)
	for _, r := range p.Restrictions {
		if !slices.Contains(have, r) {
			return false
		}
	}
	for k, v := range p.On {
		if !same(cfg[k], v) {
			return false
		}
	}
	return true
}

// same compares a value of the JSON of Headwind MDM (float64, bool, nil) with a value of a preset
func same(got, want any) bool {
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	return string(a) == string(b)
}

// SetPreset turns the preset of the device on or off in its configuration; Headwind MDM pushes the change.
func (m *Manager) SetPreset(serial, name string, on bool) error {
	p := preset(name)
	if p == nil {
		return fmt.Errorf("no preset %q", name)
	}
	dev, err := m.HW.Device(serial)
	if err != nil {
		return err
	}
	if dev == nil {
		return fmt.Errorf("%s is not an Android device of the server", serial)
	}
	cfg, err := m.HW.Configuration(dev.ConfigurationID)
	if err != nil {
		return err
	}
	if cfg.Name() != configPrefix+serial {
		return fmt.Errorf("%s uses the configuration %q of another device: enroll it again", serial, cfg.Name())
	}
	have := restrictionList(cfg)
	for _, r := range p.Restrictions {
		have = slices.DeleteFunc(have, func(x string) bool { return x == r })
		if on {
			have = append(have, r)
		}
	}
	cfg["restrictions"] = strings.Join(have, ",")
	values := p.Off
	if on {
		values = p.On
	}
	for k, v := range values {
		cfg[k] = v
	}
	if err := m.HW.SaveConfiguration(cfg); err != nil {
		return err
	}
	m.mu.Lock()
	if m.changed == nil {
		m.changed = map[string]time.Time{}
	}
	m.changed[serial] = m.now()
	m.mu.Unlock()
	return nil
}

// Send sends the command to the agent of the device.
func (m *Manager) Send(serial, name, pkg string) error {
	var c *Command
	for _, x := range Commands {
		if x.Name == name {
			c = x
		}
	}
	if c == nil {
		return fmt.Errorf("no command %q", name)
	}
	payload := ""
	if c.Package {
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$`).MatchString(pkg) {
			return fmt.Errorf("invalid package %q", pkg)
		}
		if pkg == AgentPackage {
			return errors.New("the agent itself: use Release")
		}
		data, _ := json.Marshal(map[string]string{"pkg": pkg})
		payload = string(data)
	}
	dev, err := m.HW.Device(serial)
	if err != nil {
		return err
	}
	if dev == nil {
		return fmt.Errorf("%s is not an Android device of the server", serial)
	}
	return m.HW.Push(serial, c.Push, payload)
}

// Delete removes the device and its configuration from the server; release the device first.
func (m *Manager) Delete(serial string) error {
	dev, err := m.HW.Device(serial)
	if err != nil {
		return err
	}
	if dev == nil {
		return fmt.Errorf("%s is not an Android device of the server", serial)
	}
	if err := m.HW.DeleteDevice(dev.ID); err != nil {
		return err
	}
	list, err := m.HW.Configurations()
	if err != nil {
		return err
	}
	for _, c := range list {
		if c.Name() == configPrefix+serial {
			return m.HW.DeleteConfiguration(c.ID())
		}
	}
	return nil
}
