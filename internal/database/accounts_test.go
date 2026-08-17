package database

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

func makeTLSReport(t *testing.T) *parser.TLSReport {
	t.Helper()
	var r parser.TLSReport
	err := json.Unmarshal([]byte(`{
		"organization-name": "Google Inc.",
		"date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
		"report-id": "2026-08-01_example.com",
		"policies": [{
			"policy": {"policy-type": "sts", "policy-domain": "example.com"},
			"summary": {"total-successful-session-count": 230, "total-failure-session-count": 3}
		}]
	}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

func TestAccountCRUD(t *testing.T) {
	db := openTestDB(t)

	id, err := InsertAccount(db, Account{
		Name: "test-gmail", Provider: ProviderGmail, Host: "imap.gmail.com", Port: "993",
		Username: "dmarc@example.com", AuthType: AuthOAuthRefresh, SecretEnc: "blob",
		Mailbox: "INBOX", TLS: 1, Enabled: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	acc, err := GetAccount(db, id)
	if err != nil || acc == nil {
		t.Fatalf("GetAccount: %v %v", acc, err)
	}
	if acc.Name != "test-gmail" || acc.AuthType != AuthOAuthRefresh {
		t.Errorf("account = %+v", acc)
	}

	n, err := CountEnabledAccounts(db)
	if err != nil || n != 1 {
		t.Errorf("enabled count = %d (%v), want 1", n, err)
	}
	if err := SetAccountEnabled(db, id, false); err != nil {
		t.Fatal(err)
	}
	n, _ = CountEnabledAccounts(db)
	if n != 0 {
		t.Errorf("enabled count after disable = %d, want 0", n)
	}

	if err := DeleteAccount(db, id); err != nil {
		t.Fatal(err)
	}
	acc, err = GetAccount(db, id)
	if err != nil || acc != nil {
		t.Errorf("account after delete = %v (%v), want nil", acc, err)
	}
}

func TestSeenUIDsScopedByUIDValidity(t *testing.T) {
	db := openTestDB(t)
	const acct = int64(7)

	if err := MarkUIDsSeen(db, acct, 100, []uint32{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	seen, err := GetSeenUIDs(db, acct, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || !seen[2] {
		t.Errorf("seen = %v", seen)
	}

	// A new UIDVALIDITY invalidates the cache.
	seen, err = GetSeenUIDs(db, acct, 101)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Errorf("seen after uidvalidity change = %v, want empty", seen)
	}
}

func TestTLSRPTSaveAndDuplicate(t *testing.T) {
	db := openTestDB(t)
	report := makeTLSReport(t)

	if _, err := SaveTLSRPT(db, report, "r.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	_, err := SaveTLSRPT(db, report, "r.json", []byte("{}"))
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("second save err = %v, want ErrDuplicate", err)
	}

	list, err := ListTLSRPT(db, 0, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v (%v)", list, err)
	}
	if list[0].TotalSuccess != 230 || list[0].TotalFailure != 3 {
		t.Errorf("totals = %+v", list[0])
	}
	sum, err := GetTLSRPTSummary(db, 0)
	if err != nil || sum.ReportCount != 1 || sum.TotalFailure != 3 {
		t.Errorf("summary = %+v (%v)", sum, err)
	}
}
