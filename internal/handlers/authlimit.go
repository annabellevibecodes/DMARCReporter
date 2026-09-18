package handlers

import (
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// AuthThrottle returns a middleware that blocks a client IP for `window`
// after `max` failed authentication attempts (responses with status 401)
// inside that window. It must be registered *before* the basicauth
// middleware so it can observe the 401 that basicauth produces.
//
// Unlike the generic limiter (which counts every request), only 401
// responses count, so a logged-in user browsing normally is never throttled.
func AuthThrottle(max int, window time.Duration) fiber.Handler {
	if max <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	t := &authThrottle{max: max, window: window, hits: map[string]*authHits{}}
	go t.sweep()
	return t.handle
}

type authHits struct {
	count int
	first time.Time
}

type authThrottle struct {
	max    int
	window time.Duration

	mu   sync.Mutex
	hits map[string]*authHits
}

func (t *authThrottle) handle(c *fiber.Ctx) error {
	ip := c.IP()
	now := time.Now()

	t.mu.Lock()
	h := t.hits[ip]
	if h != nil && now.Sub(h.first) > t.window {
		delete(t.hits, ip)
		h = nil
	}
	blocked := h != nil && h.count >= t.max
	t.mu.Unlock()

	if blocked {
		c.Set(fiber.HeaderRetryAfter, formatSeconds(t.window))
		return c.Status(fiber.StatusTooManyRequests).SendString("Too many failed login attempts. Try again later.")
	}

	err := c.Next()

	if c.Response().StatusCode() == fiber.StatusUnauthorized {
		t.mu.Lock()
		h := t.hits[ip]
		if h == nil || now.Sub(h.first) > t.window {
			t.hits[ip] = &authHits{count: 1, first: now}
		} else {
			h.count++
		}
		t.mu.Unlock()
	}
	return err
}

// sweep drops expired entries so the map cannot grow without bound.
func (t *authThrottle) sweep() {
	ticker := time.NewTicker(t.window)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-t.window)
		t.mu.Lock()
		for ip, h := range t.hits {
			if h.first.Before(cutoff) {
				delete(t.hits, ip)
			}
		}
		t.mu.Unlock()
	}
}

func formatSeconds(d time.Duration) string {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}
