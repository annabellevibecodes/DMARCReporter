package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
)

// The snapshot table is a change log by construction: re-observing the same
// record confirms it, it does not append a row.
func TestUpsertBIMISnapshotOnlyRecordsChanges(t *testing.T) {
	db := openTestDB(t)
	const record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"

	changed, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "Example.COM", Selector: "Default", Kind: BIMISnapshotRecord,
		Content: record, Detail: `{"state":"published"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("the first observation of a record is not a change")
	}

	if changed, err = UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord, Content: record,
	}); err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("an unchanged record must not register as a change")
	}

	history, err := ListBIMISnapshots(db, "example.com", BIMISnapshotRecord, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("rows = %d, want the repeat folded into one", len(history))
	}
	if history[0].Checks != 2 {
		t.Errorf("checks = %d, want 2", history[0].Checks)
	}
	// Domain and selector are matched case-insensitively, or one zone file
	// spelled two ways would look like two configurations.
	if history[0].Domain != "example.com" || history[0].Selector != "default" {
		t.Errorf("stored as %s/%s, want lower case", history[0].Domain, history[0].Selector)
	}

	// A new logo is a change, and both states stay readable (B5).
	const rotated = "v=BIMI1; l=https://example.com/logo-2026.svg; a=https://example.com/vmc.pem"
	if changed, err = UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord, Content: rotated,
		LastSeen: time.Now().Unix() + 60,
	}); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("a different record must register as a change")
	}
	if history, err = ListBIMISnapshots(db, "example.com", BIMISnapshotRecord, 0); err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Content != rotated {
		t.Fatalf("history = %d rows, newest %q", len(history), history[0].Content)
	}

	cur, err := GetCurrentBIMISnapshot(db, "example.com", "default", BIMISnapshotRecord)
	if err != nil || cur == nil {
		t.Fatalf("current = %v, %v", cur, err)
	}
	if cur.Content != rotated {
		t.Errorf("current content = %q, want the newest", cur.Content)
	}
}

// Selectors are separate configurations; one changing must not look like the
// other changing.
func TestBIMISnapshotsAreScopedPerSelector(t *testing.T) {
	db := openTestDB(t)
	for _, s := range []struct{ selector, content string }{
		{"default", "v=BIMI1; l=https://example.com/logo.svg"},
		{"winter", "v=BIMI1; l=https://example.com/winter.svg"},
	} {
		if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
			Domain: "example.com", Selector: s.selector, Kind: BIMISnapshotRecord, Content: s.content,
		}); err != nil {
			t.Fatal(err)
		}
	}
	current, err := ListCurrentBIMISnapshots(db, BIMISnapshotRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 2 {
		t.Fatalf("current rows = %d, want one per selector", len(current))
	}

	changed, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Selector: "winter", Kind: BIMISnapshotRecord,
		Content: "v=BIMI1; l=https://example.com/winter-2.svg", LastSeen: time.Now().Unix() + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("want a change on the winter selector")
	}
	if got, _ := GetCurrentBIMISnapshot(db, "example.com", "default", BIMISnapshotRecord); got.Content != "v=BIMI1; l=https://example.com/logo.svg" {
		t.Errorf("the default selector changed too: %q", got.Content)
	}
}

// An error is part of the observed state: a record that stops resolving is a
// change worth a row, and must not be folded into the last good observation.
func TestBIMISnapshotErrorIsPartOfTheState(t *testing.T) {
	db := openTestDB(t)
	if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord, Content: "v=BIMI1; l=https://example.com/l.svg",
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord, Content: "", Error: "server misbehaving",
		LastSeen: time.Now().Unix() + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("a lookup failure after a good record is a change")
	}
}

func TestListStaleBIMIDomains(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()

	stale, err := ListStaleBIMIDomains(db, now-3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0] != "example.com" {
		t.Fatalf("stale = %v, want the reported domain", stale)
	}

	if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord, Content: "", LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	if stale, err = ListStaleBIMIDomains(db, now-3600); err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Errorf("stale = %v, want none: a fresh lookup counts even when it found nothing", stale)
	}
	// A domain looked up long ago is due again.
	if stale, err = ListStaleBIMIDomains(db, now+3600); err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 {
		t.Errorf("stale = %v, want the domain back once its snapshot aged out", stale)
	}
}

func TestBIMISelectorInventory(t *testing.T) {
	db := openTestDB(t)
	day := int64(1767225600) // 2026-01-01

	if err := UpsertBIMISelector(db, BIMISelector{
		Domain: "Example.com", Selector: "Winter", Source: BIMISelectorPublished,
		FirstSeen: day, LastSeen: day,
	}); err != nil {
		t.Fatal(err)
	}
	// Seeing it again later must extend last_seen and keep first_seen.
	if err := UpsertBIMISelector(db, BIMISelector{
		Domain: "example.com", Selector: "winter", Source: BIMISelectorReported,
		FirstSeen: day + 86400, LastSeen: day + 86400,
	}); err != nil {
		t.Fatal(err)
	}

	sels, err := ListBIMISelectors(db, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(sels) != 1 {
		t.Fatalf("rows = %d, want the case variants collapsed into one", len(sels))
	}
	if sels[0].FirstSeen != day || sels[0].LastSeen != day+86400 {
		t.Errorf("seen window = %d..%d, want %d..%d", sels[0].FirstSeen, sels[0].LastSeen, day, day+86400)
	}
	if sels[0].Expected != -1 {
		t.Errorf("expected = %d, want -1 (unset) until the operator says", sels[0].Expected)
	}

	if err := SetBIMISelectorExpected(db, "example.com", "winter", 1); err != nil {
		t.Fatal(err)
	}
	// Marking it expected must not disturb the observation window.
	if err := UpsertBIMISelector(db, BIMISelector{
		Domain: "example.com", Selector: "winter", LastSeen: day + 2*86400,
	}); err != nil {
		t.Fatal(err)
	}
	sels, _ = ListBIMISelectors(db, "example.com")
	if sels[0].Expected != 1 {
		t.Errorf("expected = %d, want 1 to survive a later observation", sels[0].Expected)
	}
	if sels[0].FirstSeen != day {
		t.Errorf("first seen = %d, want it unchanged at %d", sels[0].FirstSeen, day)
	}

	// A selector the operator flags before it is ever seen still gets a row.
	if err := SetBIMISelectorExpected(db, "example.com", "summer", 1); err != nil {
		t.Fatal(err)
	}
	if sels, _ = ListBIMISelectors(db, "example.com"); len(sels) != 2 {
		t.Errorf("rows = %d, want the unseen selector recorded too", len(sels))
	}
}

func TestBIMIEligible(t *testing.T) {
	cases := []struct {
		name     string
		tuple    PolicyTuple
		eligible bool
		blocker  string // substring expected in the first blocker
	}{
		{"reject", PolicyTuple{P: "reject"}, true, ""},
		{"quarantine at full effect", PolicyTuple{P: "quarantine"}, true, ""},
		{"none", PolicyTuple{P: "none"}, false, "p=none"},
		{"empty policy", PolicyTuple{}, false, "p=none"},
		{
			"quarantine with sampling",
			PolicyTuple{P: "quarantine", Pct: 50, PctPresent: 1}, false, "pct=50",
		},
		{
			"quarantine with pct=100 published explicitly",
			PolicyTuple{P: "quarantine", Pct: 100, PctPresent: 1}, true, "",
		},
		{
			"DMARCbis record with no pct at all",
			PolicyTuple{P: "quarantine", Pct: 0, PctPresent: 0}, true, "",
		},
		{
			"sp=none exempts the subdomains and blocks BIMI",
			PolicyTuple{P: "reject", SP: "none", SPPresent: 1}, false, "sp=none",
		},
		{
			"sp absent inherits p and does not block",
			PolicyTuple{P: "reject", SP: "none", SPPresent: 0}, true, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eligible, blockers, _ := BIMIEligible(tc.tuple)
			if eligible != tc.eligible {
				t.Errorf("eligible = %v, want %v (blockers %v)", eligible, tc.eligible, blockers)
			}
			if tc.blocker != "" && (len(blockers) == 0 || !strings.Contains(blockers[0], tc.blocker)) {
				t.Errorf("blockers = %v, want one mentioning %q", blockers, tc.blocker)
			}
			if tc.eligible && len(blockers) != 0 {
				t.Errorf("eligible but blocked: %v", blockers)
			}
		})
	}

	// pct with p=reject is a note, not a blocker: §7.1 constrains quarantine.
	eligible, blockers, notes := BIMIEligible(PolicyTuple{P: "reject", Pct: 20, PctPresent: 1})
	if !eligible || len(blockers) != 0 || len(notes) == 0 {
		t.Errorf("reject+pct: eligible=%v blockers=%v notes=%v", eligible, blockers, notes)
	}
}

func TestGetBIMIReadinessUsesTheDominantPolicy(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()

	// The dominant report says quarantine at full effect; a second, much
	// smaller reporter still sees the old p=none.
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}
	stale := testFeedback("r2", begin)
	stale.ReportMetadata.OrgName = "outlook.com"
	stale.PolicyPublished.Policy = "none"
	stale.Records[0].Row.Count = 1
	stale.Records[1].Row.Count = 1
	if _, err := SaveReport(db, stale, "r2.xml", nil); err != nil {
		t.Fatal(err)
	}

	all, err := GetBIMIReadiness(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("rows = %d, want one per domain", len(all))
	}
	got := all[0]
	if !got.Eligible {
		t.Errorf("eligible = false (%v); the policy most mail was judged against is quarantine", got.Blockers)
	}
	if got.Messages != 112 || got.Reports != 2 {
		t.Errorf("volume = %d messages over %d reports, want 112/2", got.Messages, got.Reports)
	}

	one, err := GetBIMIReadinessFor(db, "example.com", StatsFilter{})
	if err != nil || one == nil {
		t.Fatalf("readiness for one domain: %v, %v", one, err)
	}
	if !one.Known || !one.Eligible {
		t.Errorf("known=%v eligible=%v", one.Known, one.Eligible)
	}

	// A domain nobody has reported on is unknown, not failing.
	none, err := GetBIMIReadinessFor(db, "never-reported.example", StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if none.Known || none.Eligible || len(none.Blockers) != 0 {
		t.Errorf("unreported domain = %+v, want an unknown verdict with no blockers", none)
	}
}

func TestGetDiscoveryMethod(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()

	if got, err := GetDiscoveryMethod(db, "example.com"); err != nil || got != "" {
		t.Fatalf("method = %q, %v; want empty before any report says", got, err)
	}

	f := testFeedback("r1", begin)
	f.PolicyPublished.DiscoveryMethod = "treewalk"
	if _, err := SaveReport(db, f, "r1.xml", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := GetDiscoveryMethod(db, "example.com"); err != nil || got != "treewalk" {
		t.Errorf("method = %q, %v; want treewalk", got, err)
	}
}

func TestBIMIDomainStateDecodesTheStoredLookup(t *testing.T) {
	db := openTestDB(t)
	res := bimi.Result{
		Domain: "example.com", Selector: "default", State: bimi.StateDeclined,
		FoundAt: "example.com", RRset: bimi.ParseRRset([]string{"v=BIMI1; l=; a=;"}),
	}
	detail := mustJSON(t, res)
	if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Kind: BIMISnapshotRecord,
		Content: "v=BIMI1; l=; a=;", Detail: detail,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := GetBIMIDomainState(db, "example.com")
	if err != nil || got == nil {
		t.Fatalf("state = %v, %v", got, err)
	}
	if !got.Declined() || got.Published() {
		t.Errorf("state = %q, want a declination", got.State)
	}
	if got.Result.Record.Location != "" || !got.Result.Record.LPresent {
		t.Errorf("parsed record lost the present-but-empty l=: %+v", got.Result.Record)
	}

	list, err := ListBIMIDomainStates(db, "example.com")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}

	// A snapshot with no detail still classifies from its content, so rows
	// written by an older build do not read as errors.
	if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "other.example", Kind: BIMISnapshotRecord,
		Content: "v=BIMI1; l=https://other.example/l.svg", Detail: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	other, err := GetBIMIDomainState(db, "other.example")
	if err != nil || other == nil {
		t.Fatalf("state = %v, %v", other, err)
	}
	if other.State != bimi.StatePublished {
		t.Errorf("state = %q, want %q derived from the stored record", other.State, bimi.StatePublished)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
