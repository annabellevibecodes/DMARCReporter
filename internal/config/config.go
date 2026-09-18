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
	AuthDisabled         bool          // set true (AUTH_DISABLED=true) to run without authentication — dev only
	AuthFailMax          int           // failed logins per IP per AuthFailWindow before a lockout (0 = disabled)
	AuthFailWindow       time.Duration // lockout window for AuthFailMax
	UploadRateMax        int           // max uploads per minute per IP (0 = disabled)
	FetchRateMax         int           // max IMAP fetches per 5 minutes per IP (0 = disabled)
	SecretsKey           string        // optional key for encrypting account secrets; auto-generated key file used when empty
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

	// Reporter-silence detection (R2 / X6): a reporter active in the last 14
	// days but with no report window starting in the last N days.
	AlertReporterGapDays int

	// Alert rule thresholds (X1–X11). Each is env-configurable; defaults are
	// the spec values where given, see README.
	AlertNewSourceMin        int           // X1: minimum messages before a new failing source alerts
	AlertMinWindowMessages   int           // X2/X3: minimum messages in a window for rate rules
	AlertKnownDropPts        float64       // X3: pass-rate drop (points) vs 7-day baseline for known_good sources
	AlertNewSelectorHours    int           // X4: a selector first seen within this many hours is "new"
	AlertSelectorMissingDays int           // X5: an expected selector unseen for this many days is "missing"
	AlertDNSErrorPct         float64       // X9: DNS error share (percent) per reporter
	AlertOverrideFactor      float64       // X10: overrides > factor × 7-day daily mean
	AlertSpoofFactor         float64       // X11: not-in-SPF volume > factor × 7-day daily mean …
	AlertSpoofAbs            int64         // X11: … or above this absolute count
	AlertRecentHours         int           // window for "last 24h" rules (see ANALYTICS_PLAN.md phase 5 deviation)
	AlertEvalInterval        time.Duration // daily ticker interval for time-based rules

	// TLS alert thresholds (X12–X19).
	AlertTLSRateDrop          float64 // X12: points of week-over-week drop
	AlertTLSMinWindowSessions int64   // X12: minimum sessions in both windows
	AlertTLSStripMinSessions  int64   // X13: minimum stripped sessions
	AlertTLSPolicyHostErrPct  float64 // X16: percent of a domain's sessions
	AlertTLSReporterGapDays   int     // X18: days of silence
	AlertTLSNewFailingIPMin   int64   // X19: minimum failures from a new node

	// TLSRPTRequireDKIM applies RFC 8460 §3: a TLS report that arrived as mail
	// without a valid DKIM signature is stored and shown, with its reason, but
	// left out of the T-series metrics. Reports uploaded through the web form
	// have no carrying message and are never affected.
	TLSRPTRequireDKIM bool

	// Health score weights (sum to 100 by default).
	HealthWeightPassRate    float64
	HealthWeightEnforcement float64
	HealthWeightSpoof       float64
	HealthWeightCoverage    float64
	HealthWeightAlerts      float64
	HealthWeightTLS         float64

	// Source pattern classification thresholds (S3), percent of a source's messages.
	PatternHealthyMin       int // both aligned ≥ → healthy
	PatternForwarderMin     int // DKIM-only ≥ → forwarder
	PatternBrokenSigningMin int // SPF-only ≥ → broken_signing
	PatternSpoofMin         int // neither ≥ → spoof_suspect …
	PatternSpoofMinMsgs     int // … when the source has at least this many messages
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
		AuthFailMax:          getenvInt("AUTH_FAIL_MAX", 10),
		AuthFailWindow:       getenvDuration("AUTH_FAIL_WINDOW", 15*time.Minute),
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

		AlertReporterGapDays: getenvInt("ALERT_REPORTER_GAP_DAYS", 3),

		AlertNewSourceMin:        getenvInt("ALERT_NEW_SOURCE_MIN", 10),
		AlertMinWindowMessages:   getenvInt("ALERT_MIN_WINDOW_MESSAGES", 50),
		AlertKnownDropPts:        getenvFloat("ALERT_KNOWN_DROP", 20),
		AlertNewSelectorHours:    getenvInt("ALERT_NEW_SELECTOR_HOURS", 48),
		AlertSelectorMissingDays: getenvInt("ALERT_SELECTOR_MISSING_DAYS", 7),
		AlertDNSErrorPct:         getenvFloat("ALERT_DNS_ERROR_PCT", 5),
		AlertOverrideFactor:      getenvFloat("ALERT_OVERRIDE_SPIKE_FACTOR", 3),
		AlertSpoofFactor:         getenvFloat("ALERT_SPOOF_SPIKE_FACTOR", 3),
		AlertSpoofAbs:            int64(getenvInt("ALERT_SPOOF_ABS", 50)),
		AlertRecentHours:         getenvInt("ALERT_RECENT_HOURS", 48),
		AlertEvalInterval:        getenvDuration("ALERT_EVAL_INTERVAL", 24*time.Hour),

		AlertTLSRateDrop:          getenvFloat("ALERT_TLS_RATE_DROP", 5.0),
		AlertTLSMinWindowSessions: int64(getenvInt("ALERT_TLS_MIN_WINDOW_SESSIONS", 100)),
		AlertTLSStripMinSessions:  int64(getenvInt("ALERT_TLS_STRIP_MIN_SESSIONS", 5)),
		AlertTLSPolicyHostErrPct:  getenvFloat("ALERT_TLS_POLICY_HOST_ERR_PCT", 5),
		AlertTLSReporterGapDays:   getenvInt("ALERT_TLS_REPORTER_GAP_DAYS", 3),
		AlertTLSNewFailingIPMin:   int64(getenvInt("ALERT_TLS_NEW_FAILING_IP_MIN", 10)),

		TLSRPTRequireDKIM: os.Getenv("TLSRPT_REQUIRE_DKIM") != "false",

		HealthWeightPassRate:    getenvFloat("HEALTH_W_PASS_RATE", 40),
		HealthWeightEnforcement: getenvFloat("HEALTH_W_ENFORCEMENT", 25),
		HealthWeightSpoof:       getenvFloat("HEALTH_W_SPOOF", 15),
		HealthWeightCoverage:    getenvFloat("HEALTH_W_COVERAGE", 10),
		HealthWeightAlerts:      getenvFloat("HEALTH_W_ALERTS", 10),
		HealthWeightTLS:         getenvFloat("HEALTH_W_TLS", 15),

		PatternHealthyMin:       getenvInt("PATTERN_HEALTHY_MIN", 90),
		PatternForwarderMin:     getenvInt("PATTERN_FORWARDER_MIN", 60),
		PatternBrokenSigningMin: getenvInt("PATTERN_BROKEN_SIGNING_MIN", 60),
		PatternSpoofMin:         getenvInt("PATTERN_SPOOF_MIN", 95),
		PatternSpoofMinMsgs:     getenvInt("PATTERN_SPOOF_MIN_MSGS", 5),
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
