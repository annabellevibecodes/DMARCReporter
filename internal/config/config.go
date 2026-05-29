package config

import (
	"os"
	"strconv"
)

type Config struct {
	DBPath               string
	Port                 string
	SecureCookies        bool // set true when serving over HTTPS
	HSTSEnabled          bool // set true to emit Strict-Transport-Security (implies HTTPS)
	Debug                bool // set true to emit verbose debug logs to stdout + syslog
	AuthUser             string
	AuthPassword         string
	AuthDisabled         bool // set true (AUTH_DISABLED=true) to run without authentication — dev only
	UploadRateMax        int // max uploads per minute per IP (0 = disabled)
	FetchRateMax         int // max IMAP fetches per 5 minutes per IP (0 = disabled)
	IMAPHost             string
	IMAPPort             string
	IMAPUser             string
	IMAPPass             string
	IMAPMailbox          string
	IMAPProcessedMailbox string
	IMAPTLS              bool
}

func Load() Config {
	return Config{
		DBPath:               getenv("DB_PATH", "dmarc.db"),
		Port:                 getenv("PORT", "8080"),
		SecureCookies:        os.Getenv("SECURE_COOKIES") == "true",
		HSTSEnabled:          os.Getenv("HSTS_ENABLED") == "true",
		Debug:                os.Getenv("DEBUG") == "true",
		AuthUser:             getenv("AUTH_USER", "admin"),
		AuthPassword:         os.Getenv("AUTH_PASSWORD"),
		AuthDisabled:         os.Getenv("AUTH_DISABLED") == "true",
		UploadRateMax:        getenvInt("UPLOAD_RATE_MAX", 20),
		FetchRateMax:         getenvInt("FETCH_RATE_MAX", 3),
		IMAPHost:             os.Getenv("IMAP_HOST"),
		IMAPPort:             getenv("IMAP_PORT", "993"),
		IMAPUser:             os.Getenv("IMAP_USER"),
		IMAPPass:             os.Getenv("IMAP_PASS"),
		IMAPMailbox:          getenv("IMAP_MAILBOX", "INBOX"),
		IMAPProcessedMailbox: getenv("IMAP_PROCESSED_MAILBOX", "INBOX.Processed"),
		IMAPTLS:              os.Getenv("IMAP_TLS") != "false",
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
