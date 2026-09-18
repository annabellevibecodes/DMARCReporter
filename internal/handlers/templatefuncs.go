package handlers

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
	"github.com/annabellevibecodes/dmarcreporter/internal/metrics"
)

// TemplateFuncs returns the helper functions shared by every template.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b int) int { return a + b },
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
		"metric":       metrics.Tag,
		"metricRange":  metrics.RangeTag,
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
