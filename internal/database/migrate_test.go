package database

import (
	_ "embed"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
)

//go:embed testdata/schema_v1.sql
var legacySchema string

// legacyGMXXML is a DMARCbis-namespaced report as stored by the previous
// version of the application (which did not persist version/np/testing).
const legacyGMXXML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
   <version>1.0</version>
   <report_metadata>
      <org_name>GMX</org_name>
      <report_id>legacy-1</report_id>
      <date_range><begin>1780358400</begin><end>1780444799</end></date_range>
   </report_metadata>
   <policy_published>
      <domain>legacy.example</domain>
      <discovery_method>psl</discovery_method>
      <adkim>r</adkim>
      <aspf>r</aspf>
      <p>reject</p>
      <np>quarantine</np>
      <testing>n</testing>
   </policy_published>
   <record>
      <row><source_ip>52.101.188.141</source_ip><count>1</count>
         <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
      </row>
      <identifiers><envelope_from>legacy.example</envelope_from><header_from>legacy.example</header_from></identifiers>
      <auth_results>
         <dkim><domain>legacy.example</domain><selector>selector1</selector><result>pass</result></dkim>
         <dkim><domain>third.example</domain><selector>k1</selector><result>pass</result></dkim>
      </auth_results>
   </record>
</feedback>`

// openLegacyDB creates an in-memory database with the pre-extension schema and
// one imported report the way the old SaveReport wrote it (sp=” when absent,
// pct=0 when absent, no version/np columns at all).
func openLegacyDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	res, err := db.Exec(`
		INSERT INTO reports (org_name, report_id, date_range_begin, date_range_end, domain,
			adkim, aspf, policy, subdomain_policy, pct, failure_options, imported_at, source_filename)
		VALUES ('GMX', 'legacy-1', 1780358400, 1780444799, 'legacy.example',
			'r', 'r', 'reject', '', 0, '', ?, 'legacy.xml')`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	rr, err := db.Exec(`INSERT INTO record_rows (report_id, source_ip, count, disposition, eval_dkim, eval_spf, envelope_from, header_from)
		VALUES (?, '52.101.188.141', 1, 'none', 'pass', 'pass', 'legacy.example', 'legacy.example')`, id)
	if err != nil {
		t.Fatal(err)
	}
	rrID, _ := rr.LastInsertId()
	if _, err := db.Exec(`INSERT INTO dkim_results (record_row_id, domain, selector, result) VALUES (?, 'legacy.example', 'selector1', 'pass'), (?, 'third.example', 'k1', 'pass')`, rrID, rrID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO report_xml (report_id, xml_data) VALUES (?, ?)`, id, legacyGMXXML); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMigrateLegacyDatabase(t *testing.T) {
	db := openLegacyDB(t)

	// Sanity: the legacy schema really lacks the new columns.
	var n int
	if err := db.Get(&n, `SELECT COUNT(*) FROM pragma_table_info('reports') WHERE name = 'version'`); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("legacy schema unexpectedly has a version column")
	}

	if err := migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, c := range reportColumns {
		if err := db.Get(&n, `SELECT COUNT(*) FROM pragma_table_info('reports') WHERE name = ?`, c.name); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("column reports.%s missing after migrate", c.name)
		}
	}
	for _, tbl := range []string{
		"ip_labels", "selectors", "managed_domains", "ingest_events", "alerts",
		"spf_authorized_cache", "app_meta", "bimi_snapshots", "bimi_selectors",
	} {
		if err := db.Get(&n, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?`, tbl); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("table %s missing after migrate", tbl)
		}
	}

	// Backfill populated the new columns from the stored XML and normalised
	// the absent optional tags to RFC defaults with present=0.
	r, err := GetReport(db, 1)
	if err != nil || r == nil {
		t.Fatalf("GetReport: %v %v", r, err)
	}
	if r.Version != "1.0" || r.XMLNamespace != "urn:ietf:params:xml:ns:dmarc-2.0" {
		t.Errorf("version/namespace = %q/%q", r.Version, r.XMLNamespace)
	}
	if r.NP != "quarantine" || r.DiscoveryMethod != "psl" || r.Testing != "n" {
		t.Errorf("np/discovery/testing = %q/%q/%q", r.NP, r.DiscoveryMethod, r.Testing)
	}
	if r.SPPresent != 0 || r.SubdomainPolicy != "" || r.EffectiveSubdomainPolicy() != "reject" {
		t.Errorf("sp = %q present=%d effective=%q", r.SubdomainPolicy, r.SPPresent, r.EffectiveSubdomainPolicy())
	}
	if r.PctPresent != 0 || r.Pct != 100 {
		t.Errorf("pct = %d present=%d, want 100/0", r.Pct, r.PctPresent)
	}
	if r.FOPresent != 0 || r.FailureOptions != "0" {
		t.Errorf("fo = %q present=%d, want '0'/0", r.FailureOptions, r.FOPresent)
	}
	if !r.IsDMARCbis() {
		t.Error("IsDMARCbis() = false")
	}

	sels, err := ListSelectors(db, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sels) != 2 {
		t.Fatalf("selectors = %+v, want 2", sels)
	}
	for _, s := range sels {
		if s.FirstSeen != 1780358400 || s.LastSeen != 1780358400 || s.Expected != -1 {
			t.Errorf("selector %+v has wrong span/expected", s)
		}
	}

	managed, err := ListManagedDomains(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed) != 1 || managed[0].Domain != "legacy.example" {
		t.Errorf("managed domains = %+v", managed)
	}

	// Running migrate again is a no-op (idempotent, markers set).
	if err := migrate(db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if v, _ := GetMeta(db, metaBackfillV1); v == "" {
		t.Error("backfill marker not set")
	}
}

func TestBackfillIsRepeatable(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", []byte(legacyGMXXML)); err != nil {
		t.Fatal(err)
	}
	n, err := BackfillFromXML(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("backfilled %d, want 1", n)
	}
	// Selector span widening: the XML begin (1780358400) is older than the
	// saved feedback's begin, so first_seen must move back, last_seen stay.
	sels, _ := ListSelectors(db, "legacy.example")
	if len(sels) != 1 || sels[0].FirstSeen != 1780358400 {
		t.Errorf("selectors = %+v", sels)
	}
}
