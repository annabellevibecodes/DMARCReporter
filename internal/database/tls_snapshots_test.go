package database

import (
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// A repeat observation is a confirmation, not a change: it bumps the row
// rather than writing a new one, so the table stays a change log.
func TestUpsertTLSSnapshotOnlyRecordsChanges(t *testing.T) {
	db := openTestDB(t)
	const policy = "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400"

	changed, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS, Content: policy, Detail: `{"mode":"testing"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("the first observation of a record is not a change")
	}

	// Same content again.
	if changed, err = UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS, Content: policy,
	}); err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("an unchanged record must not register as a change")
	}
	history, err := ListTLSSnapshots(db, "example.com", TLSSnapshotMTASTS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("rows = %d, want the repeat folded into one", len(history))
	}
	if history[0].Checks != 2 {
		t.Errorf("checks = %d, want 2", history[0].Checks)
	}

	// A real change: mode moves to enforce.
	enforced := "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400"
	if changed, err = UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS, Content: enforced,
		LastSeen: time.Now().Unix() + 60,
	}); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("a different policy must register as a change")
	}
	if history, err = ListTLSSnapshots(db, "example.com", TLSSnapshotMTASTS, 0); err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("rows = %d, want the old state kept alongside the new", len(history))
	}
	if history[0].Content != enforced {
		t.Error("the newest state should come first")
	}

	current, err := GetCurrentTLSSnapshot(db, "example.com", TLSSnapshotMTASTS, "")
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.Content != enforced {
		t.Errorf("current = %+v", current)
	}
}

// An error becoming a success is a change too — otherwise a policy host that
// recovers would never be recorded as fixed.
func TestUpsertTLSSnapshotTracksErrorTransitions(t *testing.T) {
	db := openTestDB(t)
	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS, Error: "HTTP 404",
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS,
		Content: "version: STSv1\nmode: testing", LastSeen: time.Now().Unix() + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("recovering from a fetch error is a change")
	}
}

func TestListStaleTLSPolicyDomains(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`INSERT INTO managed_domains (domain) VALUES ('example.com'), ('other.example')`); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	stale, err := ListStaleTLSPolicyDomains(db, now-86400)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 2 {
		t.Fatalf("stale = %v, want both domains", stale)
	}

	// A fresh check takes one out of scope; an old one leaves it in.
	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotTLSRPT, Content: "v=TLSRPTv1; rua=mailto:a@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "other.example", Kind: TLSSnapshotTLSRPT, Content: "v=TLSRPTv1; rua=mailto:b@other.example",
		FirstSeen: now - 200000, LastSeen: now - 200000,
	}); err != nil {
		t.Fatal(err)
	}

	if stale, err = ListStaleTLSPolicyDomains(db, now-86400); err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0] != "other.example" {
		t.Errorf("stale = %v, want only the domain checked long ago", stale)
	}
}

// Domains that only appear in reports are checked too, not just managed ones.
func TestListStaleTLSPolicyDomainsIncludesReportedDomains(t *testing.T) {
	db := openTestDB(t)
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1,
		tlsSTSPolicy("reported.example", "testing", 10, 0))

	stale, err := ListStaleTLSPolicyDomains(db, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range stale {
		if d == "reported.example" {
			found = true
		}
	}
	if !found {
		t.Errorf("stale = %v, want the reported domain included", stale)
	}
}

// T8 drift: what reporters applied versus what the domain publishes now.
func TestGetTLSPolicyDriftMTASTS(t *testing.T) {
	db := openTestDB(t)
	// Reported: mode=testing, mx=mx.example.com, max_age=604800.
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1,
		tlsSTSPolicy("example.com", "testing", 100, 0))

	// Published now: enforce, a different max_age, and an extra MX.
	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS,
		Content: "version: STSv1\nmode: enforce\nmx: mx.example.com\nmx: mx2.example.com\nmax_age: 86400",
	}); err != nil {
		t.Fatal(err)
	}

	drift, err := GetTLSPolicyDrift(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	byField := map[string]TLSDrift{}
	for _, d := range drift {
		byField[d.Field] = d
	}
	if len(byField) != 3 {
		t.Fatalf("drift fields = %v, want mode, max_age and mx", byField)
	}
	if byField["mode"].Published != "enforce" || byField["mode"].Reported != "testing" {
		t.Errorf("mode drift = %+v", byField["mode"])
	}
	if byField["max_age"].Published != "86400" || byField["max_age"].Reported != "604800" {
		t.Errorf("max_age drift = %+v", byField["max_age"])
	}
	if byField["mx"].Reported != "mx.example.com" {
		t.Errorf("mx drift = %+v", byField["mx"])
	}
	// The report's window is carried so the UI can say a later policy change
	// would explain the difference.
	if byField["mode"].LastReport == 0 || byField["mode"].OrgName != "google.com" {
		t.Errorf("drift should name the reporter and window: %+v", byField["mode"])
	}
}

// A policy that matches what is published produces no drift.
func TestGetTLSPolicyDriftAgreement(t *testing.T) {
	db := openTestDB(t)
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1,
		tlsSTSPolicy("example.com", "testing", 100, 0))
	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "example.com", Kind: TLSSnapshotMTASTS,
		Content: "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 604800",
	}); err != nil {
		t.Fatal(err)
	}
	drift, err := GetTLSPolicyDrift(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Errorf("drift = %+v, want none", drift)
	}
}

// Without a snapshot there is nothing to compare against, and no drift is
// invented.
func TestGetTLSPolicyDriftWithoutSnapshots(t *testing.T) {
	db := openTestDB(t)
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1,
		tlsSTSPolicy("example.com", "testing", 100, 0))

	drift, err := GetTLSPolicyDrift(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Errorf("drift = %+v, want none before Enrich has run", drift)
	}
}

// The case the brief cares about: senders still applying a TLSA RRset the
// domain no longer publishes.
func TestGetTLSPolicyDriftTLSA(t *testing.T) {
	db := openTestDB(t)
	var p parser.TLSPolicy
	p.Policy.PolicyType = "tlsa"
	p.Policy.PolicyDomain = "dane.example.com"
	p.Policy.MXHost = parser.FlexStrings{"mx1.dane.example.com"}
	p.Policy.PolicyString = parser.FlexStrings{"3 1 1 OLDKEYHASH"}
	p.Summary.TotalSuccess = 50
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1, p)

	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "dane.example.com", Kind: TLSSnapshotTLSA, Host: "mx1.dane.example.com",
		Content: "3 1 1 NEWKEYHASH",
	}); err != nil {
		t.Fatal(err)
	}

	drift, err := GetTLSPolicyDrift(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 1 {
		t.Fatalf("drift = %+v, want the stale RRset flagged", drift)
	}
	if drift[0].Kind != TLSSnapshotTLSA || drift[0].Field != "rrset" {
		t.Errorf("drift = %+v", drift[0])
	}
	if drift[0].Published != "3 1 1 NEWKEYHASH" || drift[0].Reported != "3 1 1 OLDKEYHASH" {
		t.Errorf("drift values = %+v", drift[0])
	}
}

// Formatting differences are not drift: the same RRset in another order or
// with different spacing must compare equal.
func TestGetTLSPolicyDriftTLSANormalisation(t *testing.T) {
	db := openTestDB(t)
	var p parser.TLSPolicy
	p.Policy.PolicyType = "tlsa"
	p.Policy.PolicyDomain = "dane.example.com"
	p.Policy.MXHost = parser.FlexStrings{"mx1.dane.example.com"}
	p.Policy.PolicyString = parser.FlexStrings{"3 1 1  bbbb", "3 1 1 aaaa"}
	p.Summary.TotalSuccess = 50
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1, p)

	if _, err := UpsertTLSSnapshot(db, TLSSnapshot{
		Domain: "dane.example.com", Kind: TLSSnapshotTLSA, Host: "mx1.dane.example.com",
		Content: "3 1 1 AAAA\n3 1 1 BBBB",
	}); err != nil {
		t.Fatal(err)
	}

	drift, err := GetTLSPolicyDrift(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Errorf("drift = %+v, want none: same RRset, different formatting", drift)
	}
}
