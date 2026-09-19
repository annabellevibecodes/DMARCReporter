package database

import (
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// reportColumns lists the columns added to `reports` after the original
// schema shipped, with their definitions. Existing databases gain them via
// ALTER TABLE (guarded by PRAGMA table_info) on startup; new databases get them
// from schema.sql directly.
var reportColumns = []struct{ name, def string }{
	{"version", "TEXT NOT NULL DEFAULT ''"},
	{"xml_namespace", "TEXT NOT NULL DEFAULT ''"},
	{"np", "TEXT NOT NULL DEFAULT ''"},
	{"discovery_method", "TEXT NOT NULL DEFAULT ''"},
	{"testing", "TEXT NOT NULL DEFAULT ''"},
	{"generator", "TEXT NOT NULL DEFAULT ''"},
	{"report_errors", "TEXT NOT NULL DEFAULT ''"},
	{"received_at", "INTEGER NOT NULL DEFAULT 0"},
	{"sp_present", "INTEGER NOT NULL DEFAULT 0"},
	{"pct_present", "INTEGER NOT NULL DEFAULT 0"},
	{"fo_present", "INTEGER NOT NULL DEFAULT 0"},
	// BIMI reporting hygiene (B19). Every one of these counts something the
	// report got wrong or something the parser had to tolerate, so a corpus
	// of well-formed reports leaves them all at zero.
	{"bimi_present", "INTEGER NOT NULL DEFAULT 0"},
	{"bimi_dup_tuples", "INTEGER NOT NULL DEFAULT 0"},
	{"bimi_bad_counts", "INTEGER NOT NULL DEFAULT 0"},
	{"bimi_unknown_types", "INTEGER NOT NULL DEFAULT 0"},
	{"bimi_missing_attrs", "INTEGER NOT NULL DEFAULT 0"},
	{"malformed_fields", "INTEGER NOT NULL DEFAULT 0"},
}

// domainCheckColumns lists columns added to `domain_checks` after the original
// schema: the records themselves, so the domain page can render what a domain
// publishes without making a DNS query while an HTTP request is waiting.
var domainCheckColumns = []struct{ name, def string }{
	{"dmarc_record", "TEXT NOT NULL DEFAULT ''"},
	{"dmarc_error", "TEXT NOT NULL DEFAULT ''"},
	{"mta_sts_record", "TEXT NOT NULL DEFAULT ''"},
	{"mta_sts_error", "TEXT NOT NULL DEFAULT ''"},
}

// accountColumns lists columns added to `accounts` after the original schema.
var accountColumns = []struct{ name, def string }{
	{"purpose", "TEXT NOT NULL DEFAULT 'report'"},
}

// ipInfoColumns lists columns added to `ip_info` after the original schema.
var ipInfoColumns = []struct{ name, def string }{
	{"whois_asn", "TEXT NOT NULL DEFAULT ''"},
}

// tlsrptReportColumns lists the columns added to `tlsrpt_reports` by the
// TLS-RPT analytics extension, in the same style as reportColumns.
var tlsrptReportColumns = []struct{ name, def string }{
	{"received_at", "INTEGER NOT NULL DEFAULT 0"},
	{"submitter_domain", "TEXT NOT NULL DEFAULT ''"},
	{"report_domain", "TEXT NOT NULL DEFAULT ''"},
	{"transport", "TEXT NOT NULL DEFAULT ''"},
	{"dkim_status", "TEXT NOT NULL DEFAULT 'unknown'"},
	{"dkim_domain", "TEXT NOT NULL DEFAULT ''"},
	{"dkim_selector", "TEXT NOT NULL DEFAULT ''"},
	{"dkim_stype_tlsrpt", "INTEGER NOT NULL DEFAULT 0"},
	{"dkim_matches_contact", "INTEGER NOT NULL DEFAULT 0"},
	{"dkim_detail", "TEXT NOT NULL DEFAULT ''"},
	{"multi_policy", "INTEGER NOT NULL DEFAULT 0"},
	{"unattributed_failures", "INTEGER NOT NULL DEFAULT 0"},
	{"malformed_ips", "INTEGER NOT NULL DEFAULT 0"},
	{"unknown_result_types", "INTEGER NOT NULL DEFAULT 0"},
	{"range_variance", "INTEGER NOT NULL DEFAULT 0"},
}

const (
	metaBackfillV1       = "backfill_xml_v1"
	metaSeedDomains      = "seed_managed_domains_v1"
	metaBackfillTLSRPTV1 = "backfill_tlsrpt_v1"
	metaBackfillBIMIV1   = "backfill_bimi_v1"
	metaRecheckDomainsV1 = "recheck_domain_records_v1"
)

// Open opens (or creates) the SQLite database at path and runs migrations.
func Open(path string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite supports only one writer at a time.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// migrate applies the schema, adds any columns missing from older databases,
// seeds managed_domains once, and runs the XML backfill once.
func migrate(db *sqlx.DB) error {
	// Enable WAL and foreign keys, then run the full schema (all CREATE IF NOT EXISTS).
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("exec schema: %w", err)
	}
	for _, c := range reportColumns {
		if err := ensureColumn(db.DB, "reports", c.name, c.def); err != nil {
			return err
		}
	}
	for _, c := range ipInfoColumns {
		if err := ensureColumn(db.DB, "ip_info", c.name, c.def); err != nil {
			return err
		}
	}
	for _, c := range accountColumns {
		if err := ensureColumn(db.DB, "accounts", c.name, c.def); err != nil {
			return err
		}
	}
	for _, c := range domainCheckColumns {
		if err := ensureColumn(db.DB, "domain_checks", c.name, c.def); err != nil {
			return err
		}
	}
	for _, c := range tlsrptReportColumns {
		if err := ensureColumn(db.DB, "tlsrpt_reports", c.name, c.def); err != nil {
			return err
		}
	}

	if done, err := GetMeta(db, metaSeedDomains); err != nil {
		return err
	} else if done == "" {
		n, err := SeedManagedDomains(db)
		if err != nil {
			return fmt.Errorf("seed managed domains: %w", err)
		}
		if n > 0 {
			log.Printf("migrate: seeded %d managed domain(s) from existing reports", n)
		}
		if err := SetMeta(db, metaSeedDomains, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	if done, err := GetMeta(db, metaBackfillV1); err != nil {
		return err
	} else if done == "" {
		n, err := BackfillFromXML(db, func(done, total int) {
			if total >= 200 && done%200 == 0 {
				log.Printf("migrate: backfill %d/%d reports", done, total)
			}
		})
		if err != nil {
			return fmt.Errorf("backfill: %w", err)
		}
		if n > 0 {
			log.Printf("migrate: backfilled %d report(s) from stored XML", n)
		}
		if err := SetMeta(db, metaBackfillV1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	// TLS reports imported before the extension only have their summary
	// counts; the policy, MX and failure rows come back out of raw_json.
	if done, err := GetMeta(db, metaBackfillTLSRPTV1); err != nil {
		return err
	} else if done == "" {
		res, err := BackfillTLSRPT(db)
		if err != nil {
			return fmt.Errorf("backfill tlsrpt: %w", err)
		}
		if res.Reports > 0 {
			log.Printf("migrate: backfilled %d TLS report(s) into policy/failure rows (%d multi-policy, %d unreadable)",
				res.Reports, res.MultiPolicy, res.Failed)
		}
		if err := SetMeta(db, metaBackfillTLSRPTV1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	// Domain checks recorded before the record text was cached have a
	// checked_at but no records, which the domain page would otherwise render
	// as "this domain publishes nothing". Clearing checked_at makes the
	// background refresher read them again on the next pass, and until then
	// the page says "not looked up yet" — which is true.
	if done, err := GetMeta(db, metaRecheckDomainsV1); err != nil {
		return err
	} else if done == "" {
		res, err := db.Exec(`
			UPDATE domain_checks SET checked_at = 0
			 WHERE checked_at > 0 AND dmarc_record = '' AND mta_sts_record = ''
			   AND dmarc_error = '' AND mta_sts_error = ''`)
		if err != nil {
			return fmt.Errorf("reset domain checks: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("migrate: %d domain check(s) queued for re-reading so their records can be cached", n)
		}
		if err := SetMeta(db, metaRecheckDomainsV1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	// Reports imported before BIMI reporting support carry their <bimi>
	// element only inside the stored XML.
	if done, err := GetMeta(db, metaBackfillBIMIV1); err != nil {
		return err
	} else if done == "" {
		res, err := BackfillBIMI(db)
		if err != nil {
			return fmt.Errorf("backfill bimi: %w", err)
		}
		if res.WithBIMI > 0 {
			log.Printf("migrate: backfilled BIMI data from %d of %d stored report(s): %d assertion(s), %d error tuple(s)",
				res.WithBIMI, res.Scanned, res.Assertions, res.Errors)
		}
		if err := SetMeta(db, metaBackfillBIMIV1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

// ensureColumn adds column to table when PRAGMA table_info does not list it.
func ensureColumn(db *sql.DB, table, column, def string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def)); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

// GetMeta returns the value stored under key in app_meta ("" when absent).
func GetMeta(db *sqlx.DB, key string) (string, error) {
	var v string
	err := db.Get(&v, `SELECT value FROM app_meta WHERE key = ?`, key)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetMeta stores value under key in app_meta.
func SetMeta(db *sqlx.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO app_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
