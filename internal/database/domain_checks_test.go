package database

import (
	"testing"
	"time"
)

// The domain page renders what a domain publishes without resolving anything,
// so the records themselves have to survive the round trip — not just the
// booleans.
func TestDomainCheckStoresTheRecords(t *testing.T) {
	db := openTestDB(t)

	// A domain never looked up is distinguishable from one that publishes
	// nothing: that is the whole point of CheckedAt.
	got, err := GetDomainCheck(db, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Checked() {
		t.Errorf("an unknown domain reported as checked: %+v", got)
	}

	now := time.Now().Unix()
	if err := UpsertDomainCheck(db, DomainCheck{
		Domain:       "example.com",
		HasDMARC:     1,
		HasMTASTS:    1,
		CheckedAt:    now,
		DMARCRecord:  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
		MTASTSRecord: "v=STSv1; id=20260918T000000;",
	}); err != nil {
		t.Fatal(err)
	}

	if got, err = GetDomainCheck(db, "example.com"); err != nil {
		t.Fatal(err)
	}
	if !got.Checked() {
		t.Error("a stored check reported as never looked up")
	}
	if got.DMARCRecord != "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" {
		t.Errorf("dmarc record = %q", got.DMARCRecord)
	}
	if got.MTASTSRecord != "v=STSv1; id=20260918T000000;" {
		t.Errorf("mta-sts record = %q", got.MTASTSRecord)
	}

	// A lookup failure replaces the record with the reason, and is not the
	// same as the domain publishing nothing.
	if err := UpsertDomainCheck(db, DomainCheck{
		Domain: "example.com", CheckedAt: now + 60,
		DMARCError: "server misbehaving",
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = GetDomainCheck(db, "example.com"); err != nil {
		t.Fatal(err)
	}
	if got.DMARCError != "server misbehaving" || got.DMARCRecord != "" {
		t.Errorf("after a failure: record=%q error=%q", got.DMARCRecord, got.DMARCError)
	}

	// And the bulk read returns the same fields, which the dashboard uses.
	all, err := GetAllDomainChecks(db)
	if err != nil {
		t.Fatal(err)
	}
	if all["example.com"].DMARCError != "server misbehaving" {
		t.Errorf("bulk read lost the error: %+v", all["example.com"])
	}
}

// Flipping an account between report and seed must make the next fetch walk
// the mailbox again: the two roles read different things out of one message.
func TestChangingAccountPurposeClearsTheSeenCache(t *testing.T) {
	db := openTestDB(t)
	id, err := InsertAccount(db, Account{
		Name: "seed test", Provider: ProviderIMAP, Host: "imap.example.com",
		Port: "993", Username: "a@example.com", AuthType: AuthPassword,
		Mailbox: "INBOX", TLS: 1, Enabled: 1, Purpose: PurposeReport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkUIDsSeen(db, id, 1, []uint32{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := MarkGraphIDsSeen(db, id, []string{"m1", "m2"}); err != nil {
		t.Fatal(err)
	}

	acc, err := GetAccount(db, id)
	if err != nil || acc == nil {
		t.Fatalf("get account: %v", err)
	}

	// An unrelated edit leaves the cache alone.
	acc.Mailbox = "INBOX/Reports"
	if err := UpdateAccountConfig(db, *acc); err != nil {
		t.Fatal(err)
	}
	seen, err := GetSeenUIDs(db, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Errorf("seen uids = %d after an unrelated edit, want them kept", len(seen))
	}

	// Changing the purpose purges it.
	acc.Purpose = PurposeSeed
	if err := UpdateAccountConfig(db, *acc); err != nil {
		t.Fatal(err)
	}
	if seen, err = GetSeenUIDs(db, id, 1); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Errorf("seen uids = %d after the purpose changed, want the mailbox re-read", len(seen))
	}
	graphSeen, err := GetSeenGraphIDs(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(graphSeen) != 0 {
		t.Errorf("graph ids = %d after the purpose changed", len(graphSeen))
	}

	stored, err := GetAccount(db, id)
	if err != nil || stored == nil {
		t.Fatalf("get account: %v", err)
	}
	if !stored.IsSeed() {
		t.Errorf("purpose = %q, want it persisted", stored.Purpose)
	}
}
