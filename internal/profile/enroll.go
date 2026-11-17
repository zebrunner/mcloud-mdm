// Package profile builds the configuration profiles: the enrollment profile of the MDM and the ready profiles of
// the admin UI (README.md#ready-profiles).
package profile

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"

	"howett.net/plist"
)

// Enrollment are the settings of an enrollment profile.
type Enrollment struct {
	// ID is the PayloadIdentifier of the profile, the payloads get it as their prefix
	ID        string
	OrgName   string
	ServerURL string
	SCEPURL   string
	// Topic is the UID of the APNs push certificate (com.apple.mgmt.External.<uuid>)
	Topic string
	// Challenge is the one-time challenge of SCEP of this profile
	Challenge string
	// Subject is the common name of the device identity, unique per profile: a depot may refuse a second one
	Subject string
	// TLSCA is the DER CA of a self-signed MDM server: installed and pinned for the MDM connection, none by default
	TLSCA []byte
}

// Build returns the XML plist of the enrollment profile.
func (e Enrollment) Build() ([]byte, error) {
	if e.Topic == "" {
		return nil, errors.New("no push topic: upload the APNs push certificate first")
	}
	if e.Challenge == "" || e.ServerURL == "" || e.SCEPURL == "" || e.ID == "" {
		return nil, errors.New("incomplete enrollment settings")
	}
	var payloads []any
	var pins []string
	if len(e.TLSCA) > 0 {
		root := payload("com.apple.security.root", e.ID+".tlsca", e.OrgName+" TLS CA")
		root["PayloadContent"] = e.TLSCA
		root["PayloadCertificateFileName"] = "mdm-ca.cer"
		pins = []string{root["PayloadUUID"].(string)}
		payloads = append(payloads, root)
	}
	scep := payload("com.apple.security.scep", e.ID+".scep", e.OrgName+" device identity")
	scep["PayloadContent"] = map[string]any{
		"URL":       e.SCEPURL,
		"Name":      e.OrgName,
		"Challenge": e.Challenge,
		"Keysize":   2048,
		"Key Type":  "RSA",
		// 5: signing and encryption
		"Key Usage": 5,
		"Subject":   [][][]string{{{"CN", e.Subject}}, {{"O", e.OrgName}}},
	}
	payloads = append(payloads, scep)
	mdm := payload("com.apple.mdm", e.ID+".mdm", e.OrgName)
	mdm["IdentityCertificateUUID"] = scep["PayloadUUID"]
	mdm["Topic"] = e.Topic
	mdm["ServerURL"] = e.ServerURL
	mdm["CheckInURL"] = e.ServerURL
	mdm["SignMessage"] = true
	mdm["AccessRights"] = 8191
	mdm["CheckOutWhenRemoved"] = true
	mdm["ServerCapabilities"] = []string{"com.apple.mdm.per-user-connections"}
	if len(pins) > 0 {
		mdm["ServerURLPinningCertificateUUIDs"] = pins
		mdm["CheckInURLPinningCertificateUUIDs"] = pins
	}
	payloads = append(payloads, mdm)
	return plist.MarshalIndent(map[string]any{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   e.ID,
		"PayloadUUID":         randomUUID(),
		"PayloadDisplayName":  e.OrgName + " MDM",
		"PayloadOrganization": e.OrgName,
		"PayloadScope":        "System",
		// iOS refuses an MDM payload in a profile the user cannot remove, unless it comes from ADE
		"PayloadRemovalDisallowed": false,
		"PayloadContent":           payloads,
	}, plist.XMLFormat, "\t")
}

func payload(kind, id, name string) map[string]any {
	return map[string]any{"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": id,
		"PayloadUUID": randomUUID(), "PayloadDisplayName": name}
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return formatUUID(b, 4)
}

// StableUUID is the same UUID for the same name: a reinstalled ready profile replaces the installed one.
func StableUUID(name string) string {
	sum := sha1.Sum([]byte("mcloud-mdm:" + name))
	var b [16]byte
	copy(b[:], sum[:16])
	return formatUUID(b, 5)
}

func formatUUID(b [16]byte, version byte) string {
	b[6] = b[6]&0x0f | version<<4
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
