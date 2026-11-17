package profile

import (
	"errors"
	"fmt"

	"howett.net/plist"
)

// Command is an MDM command a preset sends before its profile.
type Command struct {
	RequestType string         `json:"request_type"`
	Args        map[string]any `json:"args"`
}

// Preset is a ready profile of the admin UI.
type Preset struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Hint  string `json:"hint"`
	// ID is the PayloadIdentifier of the profile: RemoveProfile and the "installed" mark of ProfileList use it
	ID     string    `json:"identifier"`
	Params []string  `json:"params"`
	Before []Command `json:"-"`
	build  func(id string, params map[string]string) ([]any, string, error)
}

// Prefix of the identifiers of the ready profiles
const Prefix = "com.zebrunner.mcloud.mdm.preset."

func restrictions(keys map[string]any) []any {
	return []any{map[string]any{"PayloadType": "com.apple.applicationaccess", "keys": keys}}
}

// Presets are the ready profiles, checked on iOS 18.7.11 (supervised).
var Presets = []*Preset{
	{
		Name: "swupdate-delay", Title: "Hide iOS updates for 90 days", ID: Prefix + "swupdate-delay",
		Hint: "forceDelayedSoftwareUpdates + enforcedSoftwareUpdateDelay=90 (supervised): the user does not see an update " +
			"until 90 days after its release. Checked on iOS 18.7.11: iOS 18.7.12 hidden, while the DDM deferral of " +
			"softwareupdate.settings did not hide it. Deprecated in iOS 26, removed in iOS 27 (DDM only there).",
		build: func(string, map[string]string) ([]any, string, error) {
			return restrictions(map[string]any{"forceDelayedSoftwareUpdates": true, "enforcedSoftwareUpdateDelay": 90}),
				"Delay iOS updates 90 days", nil
		},
	},
	{
		Name: "bluetooth-off", Title: "Turn Bluetooth off and lock it", ID: Prefix + "bluetooth-off",
		Hint: "The Settings command turns Bluetooth off first, then allowBluetoothModification=false (supervised) locks " +
			"the setting in Settings and Control Center. Removing the profile unlocks it, Bluetooth stays off.",
		Before: []Command{{RequestType: "Settings", Args: map[string]any{"Settings": []any{map[string]any{"Item": "Bluetooth", "Enabled": false}}}}},
		build: func(string, map[string]string) ([]any, string, error) {
			return restrictions(map[string]any{"allowBluetoothModification": false}), "Bluetooth locked off", nil
		},
	},
	{
		Name: "airdrop-off", Title: "Turn AirDrop off", ID: Prefix + "airdrop-off",
		Hint: "allowAirDrop=false (supervised): AirDrop disappears from Share and Control Center, nothing can be received.",
		build: func(string, map[string]string) ([]any, string, error) {
			return restrictions(map[string]any{"allowAirDrop": false}), "AirDrop off", nil
		},
	},
	{
		Name: "erase-off", Title: "Forbid erase and own profiles", ID: Prefix + "erase-off",
		Hint: "allowEraseContentAndSettings=false and allowUIConfigurationProfileInstallation=false (supervised): no " +
			"Erase All Content and Settings, no profile installed by the user. A restore with a computer is still " +
			"possible, and the user can still remove the MDM profile (iOS requires it without ADE).",
		build: func(string, map[string]string) ([]any, string, error) {
			return restrictions(map[string]any{"allowEraseContentAndSettings": false, "allowUIConfigurationProfileInstallation": false}),
				"Erase and own profiles forbidden", nil
		},
	},
	{
		Name: "wifi-allowed-only", Title: "Wi-Fi of the allowed network only", ID: Prefix + "wifi-allowed-only",
		Params: []string{"ssid", "password", "encryption"},
		Hint: "The network of the profile (auto join) + forceWiFiToAllowedNetworksOnly (only the networks of profiles) + " +
			"forceWiFiPowerOn (Wi-Fi cannot be turned off, MDM keeps its connection). A wrong SSID or password leaves the " +
			"device without Wi-Fi and MDM: only the agent of its host recovers it over USB (removes the MDM profile, iOS " +
			"removes every MDM profile with it, and enrolls again). The password is not stored by mcloud-mdm.",
		build: func(_ string, p map[string]string) ([]any, string, error) {
			if p["ssid"] == "" {
				return nil, "", errors.New("ssid is required")
			}
			wifi := map[string]any{"SSID_STR": p["ssid"], "AutoJoin": true, "EncryptionType": "Any"}
			switch p["encryption"] {
			case "", "Any":
			case "WPA", "WPA2", "WPA3", "None":
				wifi["EncryptionType"] = p["encryption"]
			default:
				return nil, "", fmt.Errorf("encryption %q: Any, WPA, WPA2, WPA3 or None", p["encryption"])
			}
			if p["password"] != "" {
				wifi["Password"] = p["password"]
			}
			return []any{
				map[string]any{"PayloadType": "com.apple.wifi.managed", "keys": wifi},
				map[string]any{"PayloadType": "com.apple.applicationaccess", "keys": map[string]any{
					"forceWiFiToAllowedNetworksOnly": true, "forceWiFiPowerOn": true}},
			}, "Wi-Fi " + p["ssid"] + " only", nil
		},
	},
}

// FindPreset returns the preset of name.
func FindPreset(name string) (*Preset, bool) {
	for _, p := range Presets {
		if p.Name == name {
			return p, true
		}
	}
	return nil, false
}

// Build returns the XML plist of the profile of the preset; the UUIDs are stable, a reinstall replaces it.
func (p *Preset) Build(org string, params map[string]string) ([]byte, error) {
	items, name, err := p.build(p.ID, params)
	if err != nil {
		return nil, err
	}
	content := make([]any, 0, len(items))
	for i, item := range items {
		m := item.(map[string]any)
		id := fmt.Sprintf("%s.%d", p.ID, i)
		pl := map[string]any{"PayloadType": m["PayloadType"], "PayloadVersion": 1, "PayloadIdentifier": id,
			"PayloadUUID": StableUUID(id), "PayloadDisplayName": name}
		for k, v := range m["keys"].(map[string]any) {
			pl[k] = v
		}
		content = append(content, pl)
	}
	return plist.MarshalIndent(map[string]any{
		"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": p.ID, "PayloadUUID": StableUUID(p.ID),
		"PayloadDisplayName": org + ": " + name, "PayloadOrganization": org, "PayloadScope": "System",
		"PayloadContent": content,
	}, plist.XMLFormat, "\t")
}
