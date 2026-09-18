package handlers

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
)

func TestAuthThrottleBlocksAfterFailures(t *testing.T) {
	app := fiber.New()
	app.Use(AuthThrottle(3, time.Minute))
	app.Use(basicauth.New(basicauth.Config{Users: map[string]string{"admin": "pw"}}))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	do := func(auth string) int {
		req := httptest.NewRequest("GET", "/", nil)
		if auth != "" {
			req.SetBasicAuth("admin", auth)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}

	for i := 0; i < 3; i++ {
		if got := do("wrong"); got != fiber.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, got)
		}
	}
	// Fourth attempt (even with the right password) is throttled.
	if got := do("pw"); got != fiber.StatusTooManyRequests {
		t.Fatalf("after 3 failures: status = %d, want 429", got)
	}
}

func TestAuthThrottleIgnoresSuccess(t *testing.T) {
	app := fiber.New()
	app.Use(AuthThrottle(2, time.Minute))
	app.Use(basicauth.New(basicauth.Config{Users: map[string]string{"admin": "pw"}}))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/missing", func(c *fiber.Ctx) error { return fiber.ErrNotFound })

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/missing", nil)
		req.SetBasicAuth("admin", "pw")
		resp, _ := app.Test(req)
		if resp.StatusCode != fiber.StatusNotFound {
			t.Fatalf("status = %d, want 404 (non-401 errors must not count)", resp.StatusCode)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "pw")
	resp, _ := app.Test(req)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
