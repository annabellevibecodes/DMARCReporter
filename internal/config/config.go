package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DBPath               string
	Port                 string
	BaseURL              string // external base URL, used for OAuth redirect URIs
	SecureCookies        bool   // set true when serving over HTTPS
	HSTSEnabled          bool   // set true to emit Strict-Transport-Security (implies HTTPS)
	Debug                bool   // set true to emit verbose debug logs to stdout + syslog
	AuthUser             string
	AuthPassword         string
	AuthDisabled         bool // set true (AUTH_DISABLED=true) to run without authentication — dev only
	UploadRateMax        int  // max uploads per minute per IP (0 = disabled)
	FetchRateMax         int  // max IMAP fetches per 5 minutes per IP (0 = disabled)
	SecretsKey           string // optional key for encrypting account secrets; auto-generated key file used when empty
	FetchInterval        time.Duration // background fetch interval (0 = manual fetch only)
	IMAPHost             string
	IMAPPort             string
	IMAPUser             string
	IMAPPass             string
	IMAPMailbox          string
	IMAPProcessedMailbox string
	IMAPTLS              bool
	AlertWebhookURL      string  // POST target for alert notifications ("" = disabled)
	AlertPassRateDrop    float64 // alert when pass rate drops by more than this many %-points week-over-week
	SMTPHost             string  // SMTP relay for alert emails ("" = disabled)
	SMTPPort             string
	SMTPUser             string
	SMTPPass             string
	SMTPFrom             string
	SMTPTo               string
}

func Load() Config {
	port := getenv("PORT", "8080")
	return Config{
		DBPath:               getenv("DB_PATH", "dmarc.db"),
		Port:                 port,
		BaseURL:              getenv("BASE_URL", "http://localhost:"+port),
		SecureCookies:        os.Getenv("SECURE_COOKIES") == "true",
		HSTSEnabled:          os.Getenv("HSTS_ENABLED") == "true",
		Debug:                os.Getenv("DEBUG") == "true",
		AuthUser:             getenv("AUTH_USER", "admin"),
		AuthPassword:         os.Getenv("AUTH_PASSWORD"),
		AuthDisabled:         os.Getenv("AUTH_DISABLED") == "true",
		UploadRateMax:        getenvInt("UPLOAD_RATE_MAX", 20),
		FetchRateMax:         getenvInt("FETCH_RATE_MAX", 3),
		SecretsKey:           os.Getenv("SECRETS_KEY"),
		FetchInterval:        getenvDuration("FETCH_INTERVAL", 0),
		IMAPHost:             os.Getenv("IMAP_HOST"),
		IMAPPort:             getenv("IMAP_PORT", "993"),
		IMAPUser:             os.Getenv("IMAP_USER"),
		IMAPPass:             os.Getenv("IMAP_PASS"),
		IMAPMailbox:          getenv("IMAP_MAILBOX", "INBOX"),
		IMAPProcessedMailbox: os.Getenv("IMAP_PROCESSED_MAILBOX"), // empty = auto: INBOX<delim>Processed
		IMAPTLS:              os.Getenv("IMAP_TLS") != "false",
		AlertWebhookURL:      os.Getenv("ALERT_WEBHOOK_URL"),
		AlertPassRateDrop:    getenvFloat("ALERT_PASS_RATE_DROP", 5.0),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPPort:             getenv("SMTP_PORT", "587"),
		SMTPUser:             os.Getenv("SMTP_USER"),
		SMTPPass:             os.Getenv("SMTP_PASS"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
		SMTPTo:               os.Getenv("SMTP_TO"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
	}
	return fallback
}
