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
	pending map[string]time.Time
}

// NewChallenges makes the store of the challenges valid for ttl.
func NewChallenges(ttl time.Duration) *Challenges {
	return &Challenges{ttl: ttl, now: time.Now, pending: map[string]time.Time{}}
}

// New returns a fresh challenge.
func (c *Challenges) New() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire()
	c.pending[challenge] = c.now().Add(c.ttl)
	return challenge, nil
}

// Consume reports whether challenge is pending and not expired, and forgets it.
func (c *Challenges) Consume(challenge string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire()
	if _, ok := c.pending[challenge]; !ok || challenge == "" {
		return false
	}
	delete(c.pending, challenge)
	return true
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
	for k, until := range c.pending {
		if now.After(until) {
			delete(c.pending, k)
		}
	}
}
