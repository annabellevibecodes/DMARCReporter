package database

import (
	"net/mail"
	"strings"
	"testing"
	"time"
)

// seedHeaders builds the header set a seed message would arrive with.
func seedHeaders(messageID, from, date string, authResults ...string) mail.Header {
	h := mail.Header{
		"Message-Id": {"<" + messageID + ">"},
		"From":       {from},
		"Date":       {date},
	}
	if len(authResults) > 0 {
		h["Authentication-Results"] = authResults
	}
	return h
}

func TestRecordSeedVerdicts(t *testing.T) {
	db := openTestDB(t)
	date := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC1123Z)

	n, err := RecordSeedVerdicts(db, 7, seedHeaders("m1@example.com", "Marketing <news@example.com>", date,
		`mx.google.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com; `+
			`bimi=pass header.d=example.com header.selector=default policy.authority=pass policy.indicator-hash=b4252d22`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recorded = %d, want 1", n)
	}

	got, err := ListBIMIVerdicts(db, "example.com", 0, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("verdicts = %v, %v", got, err)
	}
	v := got[0]
	if v.Receiver != "mx.google.com" || v.Result != "pass" || !v.Displayed() {
		t.Errorf("verdict = %+v", v)
	}
	if v.AccountID != 7 || v.Selector != "default" || v.Authority != "pass" {
		t.Errorf("verdict = %+v", v)
	}
	// No indicator snapshot exists for this domain, so the hash comparison is
	// unknown rather than a mismatch.
	if v.Matched != -1 {
		t.Errorf("matched = %d, want -1 when there is nothing to compare against", v.Matched)
	}

	// The same message on a later pass must not be recorded twice.
	n, err = RecordSeedVerdicts(db, 7, seedHeaders("m1@example.com", "news@example.com", date,
		`mx.google.com; bimi=pass header.d=example.com header.selector=default`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("re-reading the mailbox recorded %d verdict(s) again", n)
	}
	if got, _ = ListBIMIVerdicts(db, "", 0, 10); len(got) != 1 {
		t.Errorf("verdicts = %d after re-reading", len(got))
	}
}

// The truncated hash a receiver records is compared against the logo this
// application retrieved, and only when both exist.
func TestSeedVerdictHashComparison(t *testing.T) {
	db := openTestDB(t)
	const full = "215d5054ca31f6d7aea6a316edc8824e45828fc18678fce20c8c886cb4252d22"
	if _, err := UpsertBIMISnapshot(db, BIMISnapshot{
		Domain: "example.com", Selector: "default", Kind: BIMISnapshotIndicator, Content: full,
	}); err != nil {
		t.Fatal(err)
	}
	date := time.Now().UTC().Format(time.RFC1123Z)

	if _, err := RecordSeedVerdicts(db, 1, seedHeaders("match@example.com", "a@example.com", date,
		`mx.example.net; bimi=pass header.d=example.com policy.indicator-hash=b4252d22`), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordSeedVerdicts(db, 1, seedHeaders("mismatch@example.com", "a@example.com", date,
		`mx.example.net; bimi=pass header.d=example.com policy.indicator-hash=deadbeef`), 0); err != nil {
		t.Fatal(err)
	}

	got, err := ListBIMIVerdicts(db, "example.com", 0, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("verdicts = %v, %v", got, err)
	}
	byMessage := map[string]int{}
	for _, v := range got {
		byMessage[v.MessageID] = v.Matched
	}
	if byMessage["match@example.com"] != 1 {
		t.Errorf("matching hash recorded as %d", byMessage["match@example.com"])
	}
	if byMessage["mismatch@example.com"] != 0 {
		t.Errorf("different hash recorded as %d", byMessage["mismatch@example.com"])
	}
}

// Most seed mail carries no bimi entry at all, and must produce no rows.
func TestRecordSeedVerdictsIgnoresOrdinaryMail(t *testing.T) {
	db := openTestDB(t)
	date := time.Now().UTC().Format(time.RFC1123Z)
	n, err := RecordSeedVerdicts(db, 1, seedHeaders("plain@example.com", "a@example.com", date,
		`mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("recorded = %d for a message with no bimi entry", n)
	}
	// And a message with no Authentication-Results at all.
	if n, err = RecordSeedVerdicts(db, 1, seedHeaders("none@example.com", "a@example.com", date), 0); err != nil || n != 0 {
		t.Errorf("recorded = %d, %v", n, err)
	}
}

func TestSummariseBIMIVerdicts(t *testing.T) {
	db := openTestDB(t)
	base := time.Now().UTC().AddDate(0, 0, -5)
	for i, result := range []string{"pass", "pass", "fail"} {
		date := base.AddDate(0, 0, i).Format(time.RFC1123Z)
		if _, err := RecordSeedVerdicts(db, 1, seedHeaders(
			"m"+result+string(rune('0'+i))+"@example.com", "a@example.com", date,
			`mx.google.com; bimi=`+result+` header.d=example.com header.selector=default`,
		), 0); err != nil {
			t.Fatal(err)
		}
	}

	got, err := SummariseBIMIVerdicts(db, "example.com", 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("summary = %v, %v", got, err)
	}
	s := got[0]
	if s.Messages != 3 || s.Passed != 2 {
		t.Errorf("summary = %+v, want 3 messages and 2 passes", s)
	}
	if s.LastResult != "fail" {
		t.Errorf("last result = %q, want the newest verdict", s.LastResult)
	}
	if s.PassRate < 66 || s.PassRate > 67 {
		t.Errorf("pass rate = %.1f", s.PassRate)
	}
}

// X30's query: a receiver that has passed before and does not now.
func TestFindBIMIVerdictRegressions(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()

	record := func(id, result string, when time.Time, comment string) {
		t.Helper()
		ar := `mx.google.com; bimi=` + result
		if comment != "" {
			ar += ` (` + comment + `)`
		}
		ar += ` header.d=example.com header.selector=default`
		if _, err := RecordSeedVerdicts(db, 1, seedHeaders(id, "a@example.com", when.Format(time.RFC1123Z), ar), 0); err != nil {
			t.Fatal(err)
		}
	}
	record("p1@example.com", "pass", now.AddDate(0, 0, -5), "")
	record("p2@example.com", "pass", now.AddDate(0, 0, -3), "")

	// Still passing: nothing to report.
	if got, err := FindBIMIVerdictRegressions(db, now.AddDate(0, 0, -7).Unix()); err != nil || len(got) != 0 {
		t.Fatalf("regressions = %v, %v; want none while it still passes", got, err)
	}

	record("f1@example.com", "fail", now.Add(-2*time.Hour), "could not retrieve indicator")
	got, err := FindBIMIVerdictRegressions(db, now.Add(-48*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("regressions = %+v, want one", got)
	}
	r := got[0]
	if r.Receiver != "mx.google.com" || r.Result != "fail" {
		t.Errorf("regression = %+v", r)
	}
	if r.Comment != "could not retrieve indicator" {
		t.Errorf("comment = %q, want the receiver's explanation kept", r.Comment)
	}
	if r.LastPass == 0 || r.SinceFailures != 1 {
		t.Errorf("regression = %+v", r)
	}

	// A receiver that has never passed is not a regression, however badly it
	// fares — that is a state, not a change.
	record("n1@other.example", "none", now.Add(-time.Hour), "")
	if _, err := RecordSeedVerdicts(db, 1, seedHeaders("n2@other.example", "b@other.example",
		now.Format(time.RFC1123Z), `mx.other.example; bimi=none header.d=other.example`), 0); err != nil {
		t.Fatal(err)
	}
	got, _ = FindBIMIVerdictRegressions(db, now.Add(-48*time.Hour).Unix())
	for _, r := range got {
		if r.Receiver == "mx.other.example" {
			t.Errorf("a receiver that never passed was reported as a regression: %+v", r)
		}
	}
}

// A message with no Message-ID still gets stored, and still deduplicates.
func TestSeedVerdictWithoutMessageID(t *testing.T) {
	db := openTestDB(t)
	at := time.Now().UTC().Truncate(time.Second)
	h := mail.Header{
		"From":                   {"a@example.com"},
		"Date":                   {at.Format(time.RFC1123Z)},
		"Authentication-Results": {`mx.example.net; bimi=pass header.d=example.com`},
	}
	for i := 0; i < 2; i++ {
		if _, err := RecordSeedVerdicts(db, 1, h, 0); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListBIMIVerdicts(db, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("verdicts = %d, want the duplicate collapsed", len(got))
	}
	if !strings.HasPrefix(got[0].MessageID, "no-message-id/") {
		t.Errorf("message id = %q", got[0].MessageID)
	}
}

// An Authentication-Results header is not evidence by itself: anyone who can
// send mail to the seed address can write one. Two properties keep a forged
// header from rewriting what B21 and X30 report.
func TestSeedVerdictsResistForgedHeaders(t *testing.T) {
	now := time.Now().UTC()

	t.Run("a forged header cannot invent or overwrite a verdict", func(t *testing.T) {
		db := openTestDB(t)
		genuine := func(result string, when time.Time, id string) mail.Header {
			return seedHeaders(id+"@x", "news@example.com", when.Format(time.RFC1123Z),
				"mx.google.com; bimi="+result+" header.d=example.com header.selector=default")
		}
		// The receiver showed the logo, then stopped.
		if _, err := RecordSeedVerdicts(db, 1, genuine("pass", now.AddDate(0, 0, -5), "real1"),
			now.AddDate(0, 0, -5).Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := RecordSeedVerdicts(db, 1, genuine("fail", now.Add(-2*time.Hour), "real2"),
			now.Add(-2*time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
		if got, _ := FindBIMIVerdictRegressions(db, now.Add(-48*time.Hour).Unix()); len(got) != 1 {
			t.Fatalf("setup: regressions = %d, want the real one detected", len(got))
		}

		// An attacker mails the seed address. The receiving MTA prepends its
		// own header — about the attacker's message, not the victim's domain —
		// and the attacker's forged header sits beneath it, dated a year ahead
		// to try to become the newest verdict for ever.
		attack := seedHeaders("forged@x", "spam@attacker.example",
			now.AddDate(1, 0, 0).Format(time.RFC1123Z),
			"mx.google.com; bimi=none header.d=attacker.example header.selector=default",
			"mx.google.com; bimi=pass header.d=example.com header.selector=default")
		if _, err := RecordSeedVerdicts(db, 1, attack, now.Unix()); err != nil {
			t.Fatal(err)
		}

		got, err := FindBIMIVerdictRegressions(db, now.Add(-48*time.Hour).Unix())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Error("a forged header masked the real regression")
		}
		// The forged header invented no verdict for the victim's domain.
		rows, err := ListBIMIVerdicts(db, "example.com", 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range rows {
			if v.MessageID == "forged@x" {
				t.Errorf("the attacker's message produced a verdict for example.com: %+v", v)
			}
			if v.At > now.Unix()+60 {
				t.Errorf("a verdict is dated %d, in the future", v.At)
			}
		}
	})

	t.Run("only the topmost header is recorded", func(t *testing.T) {
		db := openTestDB(t)
		// The receiving MTA prepends its own header; anything the sender wrote
		// sits beneath it and must not become a verdict of its own.
		h := seedHeaders("m@x", "news@example.com", now.Format(time.RFC1123Z),
			"mx.google.com; bimi=fail (could not retrieve indicator) header.d=example.com header.selector=default",
			"mx.google.com; bimi=pass header.d=example.com header.selector=default",
			"mx.attacker.example; bimi=pass header.d=victim.example header.selector=default")
		n, err := RecordSeedVerdicts(db, 1, h, now.Unix())
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("recorded = %d, want only the topmost header", n)
		}
		got, err := ListBIMIVerdicts(db, "", 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Result != "fail" {
			t.Fatalf("verdicts = %+v, want the receiving MTA's own result", got)
		}
		// And no verdict was invented for a domain the attacker named.
		if v, _ := ListBIMIVerdicts(db, "victim.example", 0, 10); len(v) != 0 {
			t.Errorf("a forged header created a verdict for %q", "victim.example")
		}
	})

	t.Run("the clamp holds when no server time is available", func(t *testing.T) {
		db := openTestDB(t)
		h := seedHeaders("future@x", "news@example.com", now.AddDate(5, 0, 0).Format(time.RFC1123Z),
			"mx.google.com; bimi=pass header.d=example.com header.selector=default")
		if _, err := RecordSeedVerdicts(db, 1, h, 0); err != nil {
			t.Fatal(err)
		}
		got, err := ListBIMIVerdicts(db, "example.com", 0, 10)
		if err != nil || len(got) != 1 {
			t.Fatalf("verdicts = %v, %v", got, err)
		}
		if got[0].At > now.Unix()+60 {
			t.Errorf("at = %d, want it clamped to about now (%d)", got[0].At, now.Unix())
		}
	})
}
