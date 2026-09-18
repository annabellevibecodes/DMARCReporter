package database

import (
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

func TestReporterMetricsGolden(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	day := func(n int) int64 { return now.AddDate(0, 0, -n).Truncate(24 * time.Hour).Unix() }

	save := func(org, id, domain string, begin, end, received int64, count int) {
		t.Helper()
		fb := &models.Feedback{
			Version:         "1.0",
			ReportMetadata:  models.ReportMetadata{OrgName: org, Email: org + "@example.net", ReportID: id, DateRange: models.DateRange{Begin: begin, End: end}},
			PolicyPublished: models.PolicyPublished{Domain: domain, Policy: "none"},
			Records: []models.Record{{
				Row:         models.Row{SourceIP: "10.2.0.1", Count: count, PolicyEvaluated: models.PolicyEvaluated{Disposition: "none", DKIM: "pass", SPF: "pass"}},
				Identifiers: models.Identifiers{HeaderFrom: domain, EnvelopeTo: "gmail.com"},
			}},
		}
		if _, err := SaveReportAt(db, fb, id+".xml", nil, received); err != nil {
			t.Fatal(err)
		}
	}
	// google: daily reports, latest yesterday, received ~2h after window end.
	for i := 1; i <= 5; i++ {
		save("google.com", "g"+string(rune('0'+i)), "example.com", day(i), day(i)+86399, day(i)+86399+7200, 100)
	}
	// yahoo: reported 6 days ago and 8 days ago, then silent → gap (active in 14d, silent 3d).
	save("Yahoo", "y6", "example.com", day(6), day(6)+86399, day(6)+86399+36000, 20)
	save("Yahoo", "y8", "example.com", day(8), day(8)+86399, 0, 20) // no received_at → excluded from latency
	// outlook: anomalous 48h window, unmanaged domain.
	save("Enterprise Outlook", "o2", "stray.example", day(2), day(2)+2*86400, day(2)+2*86400+3600, 5)
	// Seed managed domains from reports (as the migration does) then drop stray.example.
	if _, err := SeedManagedDomains(db); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedDomain(db, "stray.example"); err != nil {
		t.Fatal(err)
	}
	// Ingest events: two duplicates, one parse error.
	for _, ev := range []IngestEvent{
		{Source: "imap", Filename: "a.xml", Kind: "dmarc", Status: IngestStatusDuplicate, OrgName: "google.com"},
		{Source: "imap", Filename: "b.xml", Kind: "dmarc", Status: IngestStatusDuplicate, OrgName: "google.com"},
		{Source: "upload", Filename: "c.xml", Kind: "dmarc", Status: IngestStatusParseError, Error: "xml decode: EOF"},
	} {
		if err := RecordIngestEvent(db, ev); err != nil {
			t.Fatal(err)
		}
	}

	f := StatsFilter{From: day(30)}

	// R1
	inv, err := GetReporterInventory(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 3 || inv[0].OrgName != "google.com" || inv[0].Reports != 5 || inv[0].Messages != 500 || inv[0].Versions != "1.0" || inv[0].Namespaces != "rfc7489" {
		t.Errorf("R1 = %+v", inv)
	}
	if inv[0].Share < 91 || inv[0].Share > 92 { // 500 / 545
		t.Errorf("R1 share = %v", inv[0].Share)
	}

	// R2: Yahoo is silent (last begin 6d ago), google is not, outlook (2d) is not.
	gaps, err := GetReporterGaps(db, 14, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].OrgName != "Yahoo" || gaps[0].DaysSilent < 4 {
		t.Errorf("R2 = %+v", gaps)
	}
	pres, err := GetReporterPresence(db, 10)
	if err != nil {
		t.Fatal(err)
	}
	var google []int
	for _, p := range pres {
		if p.OrgName == "google.com" {
			google = p.Days
		}
	}
	if len(google) != 10 {
		t.Fatalf("R2 presence = %+v", pres)
	}
	// Days 1..5 ago present (indexes 4..8 with index 9 = today), today (9) and 6..9 ago (0..3) absent.
	for i, want := range []int{0, 0, 0, 0, 1, 1, 1, 1, 1, 0} {
		if google[i] != want {
			t.Errorf("R2 presence[%d] = %d want %d (%v)", i, google[i], want, google)
		}
	}

	// R3: google median 2h; Yahoo 1 sample of 10h (y8 excluded); outlook 1h.
	lat, err := GetReportLatency(db, f)
	if err != nil {
		t.Fatal(err)
	}
	byOrg := map[string]ReporterLatency{}
	for _, l := range lat {
		byOrg[l.OrgName] = l
	}
	if byOrg["google.com"].Samples != 5 || byOrg["google.com"].MedianHours != 2 || byOrg["google.com"].P95Hours != 2 {
		t.Errorf("R3 google = %+v", byOrg["google.com"])
	}
	if byOrg["Yahoo"].Samples != 1 || byOrg["Yahoo"].MedianHours != 10 {
		t.Errorf("R3 yahoo = %+v", byOrg["Yahoo"])
	}

	// R4
	anom, total, err := GetDateRangeAnomalies(db, f, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(anom) != 1 || anom[0].OrgName != "Enterprise Outlook" || anom[0].DurationHours != 48 {
		t.Errorf("R4 = %d %+v", total, anom)
	}

	// R5/R6 via ingest events
	counts, _ := CountIngestEvents(db, 0)
	got := map[string]int64{}
	for _, c := range counts {
		got[c.Status] += c.Count
	}
	if got[IngestStatusDuplicate] != 2 || got[IngestStatusParseError] != 1 {
		t.Errorf("R5/R6 events = %v", got)
	}
	schema, err := GetSchemaDistribution(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(schema) != 1 || schema[0].Version != "1.0" || schema[0].Reports != 8 {
		t.Errorf("R6 schema = %+v", schema)
	}

	// R7
	un, err := GetUnmanagedDomains(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(un) != 1 || un[0].Domain != "stray.example" || un[0].Messages != 5 {
		t.Errorf("R7 = %+v", un)
	}
	if err := AddManagedDomain(db, "STRAY.example"); err != nil { // case-insensitive match
		t.Fatal(err)
	}
	if un, _ = GetUnmanagedDomains(db, f); len(un) != 0 {
		t.Errorf("R7 after add = %+v", un)
	}

	// R8
	rcpt, err := GetEnvelopeToStats(db, f, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rcpt) != 1 || rcpt[0].EnvelopeTo != "gmail.com" || rcpt[0].TotalMessages != 545 || rcpt[0].PassRate != 100 {
		t.Errorf("R8 = %+v", rcpt)
	}
}

func TestPercentile(t *testing.T) {
	v := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if percentile(v, 50) != 5 || percentile(v, 95) != 10 || percentile(v, 0) != 1 {
		t.Errorf("percentile = %v %v %v", percentile(v, 50), percentile(v, 95), percentile(v, 0))
	}
	if percentile(nil, 50) != 0 {
		t.Error("empty percentile")
	}
}
