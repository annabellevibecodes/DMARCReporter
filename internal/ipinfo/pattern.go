package ipinfo

import "fmt"

// Source behaviour patterns (S3).
const (
	PatternHealthy       = "healthy"
	PatternForwarder     = "forwarder"
	PatternBrokenSigning = "broken_signing"
	PatternSpoofSuspect  = "spoof_suspect"
	PatternMixed         = "mixed"
)

// Patterns lists every pattern value in display order.
var Patterns = []string{PatternHealthy, PatternForwarder, PatternBrokenSigning, PatternSpoofSuspect, PatternMixed}

// PatternLabel returns a human-readable label for a pattern value.
func PatternLabel(p string) string {
	switch p {
	case PatternHealthy:
		return "healthy"
	case PatternForwarder:
		return "forwarder"
	case PatternBrokenSigning:
		return "broken signing"
	case PatternSpoofSuspect:
		return "spoof suspect"
	case PatternMixed:
		return "mixed"
	}
	return p
}

// Matrix is a source's 2×2 aligned-result split.
type Matrix struct {
	BothPass int64
	DKIMOnly int64
	SPFOnly  int64
	Neither  int64
}

// Total returns the sum of the four buckets.
func (m Matrix) Total() int64 { return m.BothPass + m.DKIMOnly + m.SPFOnly + m.Neither }

// PatternThresholds are the S3 cut-offs, in percent of a source's messages
// (and a message floor for the spoof bucket).
type PatternThresholds struct {
	HealthyMin       int // both_pass share ≥ this → healthy
	ForwarderMin     int // dkim_only share ≥ this → forwarder
	BrokenSigningMin int // spf_only share ≥ this → broken_signing
	SpoofMin         int // neither share ≥ this → spoof_suspect …
	SpoofMinMsgs     int // … provided total ≥ this
}

// DefaultPatternThresholds are the spec defaults.
var DefaultPatternThresholds = PatternThresholds{
	HealthyMin: 90, ForwarderMin: 60, BrokenSigningMin: 60, SpoofMin: 95, SpoofMinMsgs: 5,
}

// ClassifySourcePattern maps a matrix to a pattern using th. Order matters and
// mirrors the SQL in PatternCaseSQL: healthy, forwarder, broken_signing,
// spoof_suspect, else mixed. An empty matrix is "mixed".
func ClassifySourcePattern(m Matrix, th PatternThresholds) string {
	t := m.Total()
	if t == 0 {
		return PatternMixed
	}
	switch {
	case m.BothPass*100 >= int64(th.HealthyMin)*t:
		return PatternHealthy
	case m.DKIMOnly*100 >= int64(th.ForwarderMin)*t:
		return PatternForwarder
	case m.SPFOnly*100 >= int64(th.BrokenSigningMin)*t:
		return PatternBrokenSigning
	case m.Neither*100 >= int64(th.SpoofMin)*t && t >= int64(th.SpoofMinMsgs):
		return PatternSpoofSuspect
	}
	return PatternMixed
}

// PatternFromClassification maps a user classification (ip_labels) to the
// pattern it overrides with; "" means no override.
func PatternFromClassification(c string) string {
	switch c {
	case "known_good":
		return PatternHealthy
	case "forwarder":
		return PatternForwarder
	case "suspicious":
		return PatternSpoofSuspect
	}
	return ""
}

// EffectivePattern applies a user classification override on top of the
// computed pattern.
func EffectivePattern(m Matrix, classification string, th PatternThresholds) string {
	if p := PatternFromClassification(classification); p != "" {
		return p
	}
	return ClassifySourcePattern(m, th)
}

// PatternCaseSQL returns a SQL CASE expression computing the same pattern as
// ClassifySourcePattern, given column expressions for the four buckets and an
// optional classification column expression (pass "" to skip overrides).
// Thresholds are embedded as integer literals (never user input).
func PatternCaseSQL(th PatternThresholds, bothPass, dkimOnly, spfOnly, neither, classification string) string {
	total := fmt.Sprintf("((%s)+(%s)+(%s)+(%s))", bothPass, dkimOnly, spfOnly, neither)
	core := fmt.Sprintf(`CASE
		WHEN %[1]s = 0 THEN '%[10]s'
		WHEN (%[2]s)*100 >= %[6]d*%[1]s THEN '%[11]s'
		WHEN (%[3]s)*100 >= %[7]d*%[1]s THEN '%[12]s'
		WHEN (%[4]s)*100 >= %[8]d*%[1]s THEN '%[13]s'
		WHEN (%[5]s)*100 >= %[9]d*%[1]s AND %[1]s >= %[14]d THEN '%[15]s'
		ELSE '%[10]s' END`,
		total, bothPass, dkimOnly, spfOnly, neither,
		th.HealthyMin, th.ForwarderMin, th.BrokenSigningMin, th.SpoofMin,
		PatternMixed, PatternHealthy, PatternForwarder, PatternBrokenSigning,
		th.SpoofMinMsgs, PatternSpoofSuspect)
	if classification == "" {
		return core
	}
	return fmt.Sprintf(`CASE
		WHEN %[1]s = 'known_good' THEN '%[2]s'
		WHEN %[1]s = 'forwarder' THEN '%[3]s'
		WHEN %[1]s = 'suspicious' THEN '%[4]s'
		ELSE %[5]s END`,
		classification, PatternHealthy, PatternForwarder, PatternSpoofSuspect, core)
}
