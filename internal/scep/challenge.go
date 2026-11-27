package scep

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Challenges are the one-time challenge passwords of the enrollment profiles: each profile gets its own, which signs
// one certificate within its time to live, so a leaked profile does not let anybody get identities later.
type Challenges struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	pending map[string]pending
}

// pending: a challenge until its expiry, for the device udid when it is bound to one
type pending struct {
	until time.Time
	udid  string
}

// SubjectPrefix starts the common name of the device identity of the profile of a udid: the CSR of a challenge bound
// to the udid has it
func SubjectPrefix(udid string) string {
	return "mcloud-mdm-" + udid + "-"
}

// NewChallenges makes the store of the challenges valid for ttl.
func NewChallenges(ttl time.Duration) *Challenges {
	return &Challenges{ttl: ttl, now: time.Now, pending: map[string]pending{}}
}

// New returns a fresh challenge.
func (c *Challenges) New() (string, error) {
	return c.NewFor("")
}

// NewFor returns a fresh challenge bound to the device udid (none: any): it signs only a CSR of the subject of that
// device (SubjectPrefix).
func (c *Challenges) NewFor(udid string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire()
	c.pending[challenge] = pending{until: c.now().Add(c.ttl), udid: udid}
	return challenge, nil
}

// Consume reports whether challenge is pending and not expired, and forgets it.
func (c *Challenges) Consume(challenge string) bool {
	_, ok := c.Take(challenge)
	return ok
}

// Take forgets challenge and returns the udid it is bound to ("" for any) and whether it was pending and not expired.
func (c *Challenges) Take(challenge string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire()
	p, ok := c.pending[challenge]
	if !ok || challenge == "" {
		return "", false
	}
	delete(c.pending, challenge)
	return p.udid, true
}

// Pending is the number of the challenges not used and not expired.
func (c *Challenges) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire()
	return len(c.pending)
}

func (c *Challenges) expire() {
	now := c.now()
	for k, p := range c.pending {
		if now.After(p.until) {
			delete(c.pending, k)
		}
	}
}
