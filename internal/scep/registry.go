package scep

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Origins of the identities of the registry
const (
	// OriginEnrollment: signed for the one-time challenge of an enrollment profile
	OriginEnrollment = "enrollment"
	// OriginRenewal: signed for a renewal (RenewalReq) of a known identity
	OriginRenewal = "renewal"
	// OriginAdopted: issued before the registry, known since its first renewal (Server.adopt)
	OriginAdopted = "adopted"
)

// keepExpired is how long the registry keeps an expired identity (the admin UI shows it, then it goes)
const keepExpired = 30 * 24 * time.Hour

// subjectPattern is the common name of the identity of a device: SubjectPrefix of its udid and 8 hex digits
var subjectPattern = regexp.MustCompile(`^mcloud-mdm-([0-9A-Fa-f-]{20,64})-[0-9A-Fa-f]{8}$`)

// UDIDOfSubject returns the udid of the common name of a device identity, "" when the name has none (an identity of
// a profile without a udid).
func UDIDOfSubject(cn string) string {
	if m := subjectPattern.FindStringSubmatch(cn); m != nil {
		return m[1]
	}
	return ""
}

// Identity is a device identity the CA signed.
type Identity struct {
	// Serial is the serial number of the certificate in lower case hex
	Serial  string `json:"serial"`
	Subject string `json:"subject"`
	// UDID is the device of the enrollment profile, empty for a profile without a udid
	UDID string `json:"udid,omitempty"`
	// Node is the node that asked for the enrollment profile (X-MCloud-Node of the proxy), empty when unknown
	Node     string `json:"node,omitempty"`
	Origin   string `json:"origin"`
	IssuedAt string `json:"issued_at"`
	NotAfter string `json:"not_after"`
	// Parent is the identity a renewal replaces
	Parent    string `json:"parent,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Revoked reports whether the identity is revoked.
func (i Identity) Revoked() bool { return i.RevokedAt != "" }

type registryData struct {
	// Since is the start of the registry: every identity signed after it is in it
	Since      string               `json:"since"`
	Identities map[string]*Identity `json:"identities"`
}

// Registry keeps the device identities the CA signed and their revocations (identities.json of the data directory,
// mode 600): a renewal is signed for a known identity that is not revoked only.
type Registry struct {
	mu   sync.Mutex
	path string
	data registryData
	Now  func() time.Time
}

// SerialOf is the serial of a certificate in the registry.
func SerialOf(cert *x509.Certificate) string {
	return cert.SerialNumber.Text(16)
}

// OpenRegistry reads the registry of the file or starts it now.
func OpenRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, Now: time.Now}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &r.data); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if r.data.Identities == nil {
		r.data.Identities = map[string]*Identity{}
	}
	if _, err := time.Parse(time.RFC3339, r.data.Since); err != nil {
		r.data.Since = r.Now().UTC().Format(time.RFC3339)
		if err := r.save(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Since is the start of the registry.
func (r *Registry) Since() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, _ := time.Parse(time.RFC3339, r.data.Since)
	return t
}

func (r *Registry) now() string { return r.Now().UTC().Format(time.RFC3339) }

// save writes the file atomically and drops the identities expired long ago; the caller holds the lock
func (r *Registry) save() error {
	limit := r.Now().Add(-keepExpired)
	for serial, id := range r.data.Identities {
		if t, err := time.Parse(time.RFC3339, id.NotAfter); err == nil && t.Before(limit) {
			delete(r.data.Identities, serial)
		}
	}
	raw, err := json.MarshalIndent(&r.data, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// Get returns the identity of the serial.
func (r *Registry) Get(serial string) (Identity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.data.Identities[serial]
	if !ok {
		return Identity{}, false
	}
	return *id, true
}

// Record adds a signed identity of the certificate.
func (r *Registry) Record(cert *x509.Certificate, id Identity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id.Serial, id.Subject = SerialOf(cert), cert.Subject.CommonName
	id.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	if id.IssuedAt == "" {
		id.IssuedAt = r.now()
	}
	r.data.Identities[id.Serial] = &id
	return r.save()
}

// revoke revokes the identities match selects that are not revoked yet; the caller holds the lock
func (r *Registry) revoke(reason string, match func(*Identity) bool) ([]Identity, error) {
	var out []Identity
	now := r.now()
	for _, id := range r.data.Identities {
		if !id.Revoked() && match(id) {
			id.RevokedAt, id.Reason = now, reason
			out = append(out, *id)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	return out, r.save()
}

// RevokeSerial revokes the identity of the serial; it reports whether there was one not revoked.
func (r *Registry) RevokeSerial(serial, reason string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, err := r.revoke(reason, func(id *Identity) bool { return id.Serial == serial })
	return len(out) > 0, err
}

// RevokeUDID revokes the identities of the device but the one of the serial except (none: "").
func (r *Registry) RevokeUDID(udid, reason, except string) ([]Identity, error) {
	if udid == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoke(reason, func(id *Identity) bool { return id.UDID == udid && id.Serial != except })
}

// RevokeNode revokes the identities of the profiles the node asked for until the time (zero: any time), with the ones
// renewed from them.
func (r *Registry) RevokeNode(node, reason string, until time.Time) ([]Identity, error) {
	if node == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoke(reason, func(id *Identity) bool {
		if id.Node != node {
			return false
		}
		if until.IsZero() {
			return true
		}
		// the lineage of a renewal keeps the time of its enrollment: a renewal after the revocation of the node is
		// still of a profile of the node before it
		t, err := time.Parse(time.RFC3339, r.enrolledAt(id))
		return err == nil && !t.After(until)
	})
}

// enrolledAt is the time of the enrollment of the lineage of the identity; the caller holds the lock
func (r *Registry) enrolledAt(id *Identity) string {
	seen := map[string]bool{}
	for id.Parent != "" && !seen[id.Serial] {
		seen[id.Serial] = true
		parent, ok := r.data.Identities[id.Parent]
		if !ok {
			break
		}
		id = parent
	}
	return id.IssuedAt
}

// RevokeChildren revokes the identities renewed from the serial (a newer renewal replaces them).
func (r *Registry) RevokeChildren(parent, reason, except string) ([]Identity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoke(reason, func(id *Identity) bool { return id.Parent == parent && id.Serial != except })
}

// Active reports whether the device has an identity that is not revoked nor expired.
func (r *Registry) Active(udid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	for _, id := range r.data.Identities {
		if id.UDID != udid || id.Revoked() {
			continue
		}
		if t, err := time.Parse(time.RFC3339, id.NotAfter); err == nil && t.After(now) {
			return true
		}
	}
	return false
}

// Nodes are the nodes of the identities that are not revoked.
func (r *Registry) Nodes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := map[string]bool{}
	for _, id := range r.data.Identities {
		if id.Node != "" && !id.Revoked() {
			set[id.Node] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// List returns a copy of the identities, the newest first.
func (r *Registry) List() []Identity {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Identity, 0, len(r.data.Identities))
	for _, id := range r.data.Identities {
		out = append(out, *id)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt != out[j].IssuedAt {
			return out[i].IssuedAt > out[j].IssuedAt
		}
		return out[i].Serial < out[j].Serial
	})
	return out
}

// NodeStatus is a node of STF: revoked (since RevokedAt) or active.
type NodeStatus struct {
	Label     string
	Revoked   bool
	RevokedAt time.Time
}

// RevokeNodes revokes the identities of the nodes STF revoked (the profiles they asked for until their revocation)
// and of the nodes it no longer has (STF deletes a revoked node only); an empty list of STF deletes nothing (a new
// database of STF is no revocation).
func (r *Registry) RevokeNodes(nodes []NodeStatus) ([]Identity, error) {
	known := map[string]bool{}
	var out []Identity
	for _, n := range nodes {
		known[n.Label] = true
		if !n.Revoked {
			continue
		}
		revoked, err := r.RevokeNode(n.Label, "node revoked", n.RevokedAt)
		out = append(out, revoked...)
		if err != nil {
			return out, err
		}
	}
	if len(nodes) == 0 {
		return out, nil
	}
	for _, node := range r.Nodes() {
		if known[node] {
			continue
		}
		revoked, err := r.RevokeNode(node, "node deleted", time.Time{})
		out = append(out, revoked...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
