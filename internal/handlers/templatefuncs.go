package handlers

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
	"github.com/annabellevibecodes/dmarcreporter/internal/metrics"
)

// TemplateFuncs returns the helper functions shared by every template.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"add":   func(a, b int) int { return a + b },
		"add64": func(a, b int64) int64 { return a + b },
		"div": func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"unixTime": func(ts int64) string {
			return time.Unix(ts, 0).UTC().Format("2006-01-02")
		},
		"unixDateTime": func(ts int64) string {
			if ts == 0 {
				return "—"
			}
			return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04")
		},
		"pct": func(f float64) string {
			return fmt.Sprintf("%.1f", f*100)
		},
		"pct1": func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"pct0": func(f float64) string { return fmt.Sprintf("%.0f", f) },
		"splitComma": func(s string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, ",")
		},
		"commaN": commaN,
		"ago": func(ts int64) string {
			if ts == 0 {
				return "never"
			}
			d := time.Since(time.Unix(ts, 0))
			switch {
			case d < time.Hour:
				return "just now"
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			case d < 48*time.Hour:
				return "yesterday"
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		// Metric identifiers (C5, S4, …) render as a link to their Help entry
		// carrying a one-line tooltip; see internal/metrics.
		"metric":      metrics.Tag,
		"metricRange": metrics.RangeTag,
		// BIMI record states and finding severities, as badge classes. Absent
		// is deliberately neutral rather than a failure: a domain that does not
		// do BIMI is not a domain doing BIMI badly.
		"bimiStateClass": func(state string) string {
			switch state {
			case bimi.StatePublished:
				return "pass"
			case bimi.StateInvalid:
				return "fail"
			case bimi.StateDeclined, bimi.StateError:
				return "warn"
			}
			return "neutral"
		},
		"bimiStateLabel": func(state string) string {
			switch state {
			case bimi.StatePublished:
				return "published"
			case bimi.StateInvalid:
				return "not usable"
			case bimi.StateDeclined:
				return "declines"
			case bimi.StateError:
				return "lookup failed"
			}
			return "no record"
		},
		"bimiSeverityClass": func(severity string) string {
			switch severity {
			case bimi.SeverityError:
				return "fail"
			case bimi.SeverityWarning:
				return "warn"
			}
			return "neutral"
		},
		"patternLabel": ipinfo.PatternLabel,
		"patternClass": func(p string) string {
			switch p {
			case ipinfo.PatternHealthy:
				return "pass"
			case ipinfo.PatternSpoofSuspect:
				return "fail"
			case ipinfo.PatternBrokenSigning:
				return "warn"
			case ipinfo.PatternForwarder:
				return "neutral"
			}
			return "warn"
		},
		"passClass": func(rate float64) string {
			switch {
			case rate >= 90:
				return ""
			case rate >= 60:
				return "mid"
			}
			return "low"
		},
		"share": func(part, total int64) float64 {
			if total == 0 {
				return 0
			}
			return float64(part) / float64(total) * 100
		},
		"widthPct": func(part, total int64) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.2f", math.Min(100, float64(part)/float64(total)*100))
		},
		"deref": func(p *float64) float64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"seq": func(n int) []int {
			s := make([]int, n)
			for i := range s {
				s[i] = i
			}
			return s
		},
		// Column sorting: the link flips direction when the column is already
		// the sorted one, so a second click reverses rather than doing nothing.
		"sortHref": func(path string, base template.URL, key, curSort, curDir string) template.URL {
			dir := "desc"
			if key == curSort && curDir == "desc" {
				dir = "asc"
			}
			return template.URL(fmt.Sprintf("%s?%s&sort=%s&dir=%s", path, base, key, dir))
		},
		"sortMark": func(key, curSort, curDir string) string {
			if key != curSort {
				return ""
			}
			if curDir == "asc" {
				return " ▲"
			}
			return " ▼"
		},
		"sortClass": func(key, curSort string) string {
			if key == curSort {
				return "sorted"
			}
			return ""
		},
		"lower":     strings.ToLower,
		"hasPrefix": strings.HasPrefix,
		"orNone": func(s string) string {
			if s == "" {
				return "none"
			}
			return s
		},
		"orDefault": func(s, d string) string {
			if s == "" {
				return d
			}
			return s
		},
	}
}
