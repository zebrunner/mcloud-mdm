package profile

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func payloads(t *testing.T, m map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, p := range m["PayloadContent"].([]any) {
		pm := p.(map[string]any)
		out[pm["PayloadType"].(string)] = pm
	}
	return out
}

func TestEnrollment(t *testing.T) {
	e := Enrollment{ID: "com.example.mdm", OrgName: "Org", ServerURL: "https://m.example.com/mdm",
		SCEPURL: "https://m.example.com/scep", Topic: "com.apple.mgmt.External.x", Challenge: "c1", Subject: "dev-1"}
	data, err := e.Build()
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, data)
	if m["PayloadIdentifier"] != "com.example.mdm" || m["PayloadRemovalDisallowed"] != false {
		t.Errorf("profile: %v", m)
	}
	p := payloads(t, m)
	if _, ok := p["com.apple.security.root"]; ok {
		t.Error("a root CA without TLSCA")
	}
	scep := p["com.apple.security.scep"]["PayloadContent"].(map[string]any)
	if scep["Challenge"] != "c1" || scep["URL"] != "https://m.example.com/scep" {
		t.Errorf("scep: %v", scep)
	}
	mdm := p["com.apple.mdm"]
	if mdm["Topic"] != "com.apple.mgmt.External.x" || mdm["ServerURL"] != "https://m.example.com/mdm" ||
		mdm["IdentityCertificateUUID"] != p["com.apple.security.scep"]["PayloadUUID"] || mdm["SignMessage"] != true {
		t.Errorf("mdm: %v", mdm)
	}
	if _, ok := mdm["ServerURLPinningCertificateUUIDs"]; ok {
		t.Error("pinning without TLSCA")
	}
}

func TestEnrollmentPinsTLSCA(t *testing.T) {
	e := Enrollment{ID: "id", OrgName: "Org", ServerURL: "https://x/mdm", SCEPURL: "http://x/scep", Topic: "t",
		Challenge: "c", Subject: "s", TLSCA: []byte{1, 2, 3}}
	data, err := e.Build()
	if err != nil {
		t.Fatal(err)
	}
	p := payloads(t, decode(t, data))
	root := p["com.apple.security.root"]
	pins := p["com.apple.mdm"]["ServerURLPinningCertificateUUIDs"].([]any)
	if root == nil || len(pins) != 1 || pins[0] != root["PayloadUUID"] {
		t.Errorf("pinning: %v %v", root, pins)
	}
}

func TestEnrollmentNeedsTopic(t *testing.T) {
	if _, err := (Enrollment{ID: "id", ServerURL: "u", SCEPURL: "s", Challenge: "c"}).Build(); err == nil ||
		!strings.Contains(err.Error(), "push") {
		t.Errorf("no error about the push certificate: %v", err)
	}
}

func TestPresets(t *testing.T) {
	for _, p := range Presets {
		params := map[string]string{"ssid": "Farm", "password": "secret", "encryption": "WPA2"}
		data, err := p.Build("Org", params)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		m := decode(t, data)
		if m["PayloadIdentifier"] != p.ID || m["PayloadUUID"] != StableUUID(p.ID) {
			t.Errorf("%s: identifier %v uuid %v", p.Name, m["PayloadIdentifier"], m["PayloadUUID"])
		}
		again, _ := p.Build("Org", params)
		if string(again) != string(data) {
			t.Errorf("%s: two builds differ", p.Name)
		}
	}
	wifi, _ := FindPreset("wifi-allowed-only")
	data, _ := wifi.Build("Org", map[string]string{"ssid": "Farm", "password": "secret", "encryption": "WPA2"})
	p := payloads(t, decode(t, data))
	if p["com.apple.wifi.managed"]["SSID_STR"] != "Farm" || p["com.apple.wifi.managed"]["Password"] != "secret" ||
		p["com.apple.applicationaccess"]["forceWiFiToAllowedNetworksOnly"] != true {
		t.Errorf("wifi: %v", p)
	}
	if _, err := wifi.Build("Org", map[string]string{"ssid": ""}); err == nil {
		t.Error("an empty SSID is accepted")
	}
	if _, err := wifi.Build("Org", map[string]string{"ssid": "x", "encryption": "ROT13"}); err == nil {
		t.Error("an unknown encryption is accepted")
	}
	bt, _ := FindPreset("bluetooth-off")
	if len(bt.Before) != 1 || bt.Before[0].RequestType != "Settings" {
		t.Errorf("bluetooth before: %v", bt.Before)
	}
}

func TestStableUUID(t *testing.T) {
	a, b := StableUUID("x"), StableUUID("x")
	if a != b || a == StableUUID("y") || len(a) != 36 || a[14] != '5' {
		t.Errorf("uuid %s %s", a, b)
	}
}
