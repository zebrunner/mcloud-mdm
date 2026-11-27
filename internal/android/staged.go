package android

import (
	"encoding/json"
	"errors"
	"strings"
)

// The staged form of the agent (its status lists the feature "staged", Android 9+ where content write exists): the
// parameters of setup and release go to the provider on the stdin of
//
//	content write --uri content://com.hmdm.launcher.mcloud/<setup|release>
//
// then `content call --method <setup|release>` without arguments uses them. The arguments of every process on the
// device are readable by every process of the shell uid (/proc/<pid>/cmdline): the secret goes there no more.
const (
	// StagedFeature is the feature of the status of an agent with the staged form
	StagedFeature = "staged"
	// StagedMinSDK is the first Android with content write (Android 9)
	StagedMinSDK = 28
)

// Staged is the JSON of the staged setup: the names of the extras of the argument form, the base URL that is --arg
// there.
type Staged struct {
	BaseURL       string `json:"baseUrl"`
	ServerProject string `json:"serverProject,omitempty"`
	DeviceID      string `json:"deviceId"`
	Secret        string `json:"secret"`
	Token         string `json:"token"`
	MQTTPort      int    `json:"mqttPort,omitempty"`
	CA            string `json:"ca,omitempty"`
	Pin           string `json:"pin,omitempty"`
}

// StagedJSON is the JSON of the staged setup on one line, for a single-quoted shell word: none of its values has a
// quote (the URL, the serial, the secret and the pins are checked, the CA is base64).
func (s *Staged) StagedJSON() (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(string(raw), "'\n") {
		return "", errors.New("the staged setup has a quote or a line end")
	}
	return string(raw), nil
}

// StagedRelease is the JSON of the staged release: the secret as the token.
func (m *Manager) StagedRelease() string {
	raw, _ := json.Marshal(map[string]string{"token": m.Secret})
	return string(raw)
}
