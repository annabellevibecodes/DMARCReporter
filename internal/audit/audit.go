// Package audit writes structured audit events to syslog (falling back to
// stderr if syslog is unavailable).  When debug mode is enabled, all messages
// are also written to stdout regardless of syslog availability.
package audit

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
)

var (
	sl          *syslog.Writer
	debugMode   bool
	debugLogger = log.New(os.Stdout, "[debug] ", log.Ldate|log.Ltime|log.Lmicroseconds)
)

// Init connects to the local syslog daemon.
// If syslog is unavailable the package falls back to stderr automatically.
func Init() {
	var err error
	sl, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "dmarcreporter")
	if err != nil {
		log.Printf("audit: syslog unavailable, falling back to stderr: %v", err)
		sl = nil
	}
}

// EnableDebug turns on verbose debug logging to stdout (and syslog if available).
func EnableDebug() {
	debugMode = true
	debugLogger.Println("debug mode enabled")
}

// Debug emits a debug-level message when debug mode is on.
// The message is written to stdout and to syslog (LOG_DEBUG).
func Debug(format string, args ...interface{}) {
	if !debugMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	debugLogger.Print(msg)
	if sl != nil {
		_ = sl.Debug(msg)
	}
}

// ReportImported logs a successful report import.
func ReportImported(source, org, domain, reportID string, recordCount int) {
	write(syslog.LOG_INFO,
		fmt.Sprintf("action=report_imported source=%q org=%q domain=%q report_id=%q records=%d",
			source, org, domain, reportID, recordCount))
}

// ReportDuplicate logs a skipped duplicate report.
func ReportDuplicate(source, org, reportID string) {
	write(syslog.LOG_INFO,
		fmt.Sprintf("action=report_duplicate source=%q org=%q report_id=%q",
			source, org, reportID))
}

// ReportParseFailed logs a parse failure (no user-controlled detail is included).
func ReportParseFailed(source string) {
	write(syslog.LOG_WARNING,
		fmt.Sprintf("action=report_parse_failed source=%q", source))
}

// IMAPFetchStarted logs the beginning of an IMAP fetch.
func IMAPFetchStarted(mailbox string) {
	write(syslog.LOG_INFO,
		fmt.Sprintf("action=imap_fetch_started mailbox=%q", mailbox))
}

// IMAPFetchCompleted logs the outcome of an IMAP fetch.
func IMAPFetchCompleted(mailbox string, imported int) {
	write(syslog.LOG_INFO,
		fmt.Sprintf("action=imap_fetch_completed mailbox=%q imported=%d", mailbox, imported))
}

// IMAPFetchFailed logs an IMAP fetch error (no internal error detail is included).
func IMAPFetchFailed(mailbox string) {
	write(syslog.LOG_ERR,
		fmt.Sprintf("action=imap_fetch_failed mailbox=%q", mailbox))
}

func write(priority syslog.Priority, msg string) {
	// Always print to stdout in debug mode.
	if debugMode {
		debugLogger.Printf("[%s] %s", priorityName(priority), msg)
	}
	if sl != nil {
		switch priority {
		case syslog.LOG_INFO:
			_ = sl.Info(msg)
		case syslog.LOG_WARNING:
			_ = sl.Warning(msg)
		case syslog.LOG_ERR:
			_ = sl.Err(msg)
		default:
			_ = sl.Info(msg)
		}
		return
	}
	// Fallback to stderr via the standard logger.
	log.Printf("[audit] %s", msg)
}

func priorityName(p syslog.Priority) string {
	switch p {
	case syslog.LOG_ERR:
		return "ERROR"
	case syslog.LOG_WARNING:
		return "WARN"
	default:
		return "INFO"
	}
}
