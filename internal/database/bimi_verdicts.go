package database

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
)

// Account purposes.
const (
	// PurposeReport is a mailbox that receives DMARC and TLS reports. Every
	// account is this unless the operator says otherwise.
	PurposeReport = "report"
	// PurposeSeed is a mailbox that receives the operator's own mail, read for
	// the BIMI verdicts receivers stamp on it. Nothing is extracted from it
	// but headers, and no report is ever imported from it.
	PurposeSeed = "seed"
)

// BIMIVerdict is one receiver's judgement of one seed message (B21).
type BIMIVerdict struct {
	ID            int64  `db:"id" json:"id"`
	AccountID     int64  `db:"account_id" json:"account_id"`
	MessageID     string `db:"message_id" json:"message_id"`
	At            int64  `db:"at" json:"at"`
	Receiver      string `db:"receiver" json:"receiver"`
	FromDomain    string `db:"from_domain" json:"from_domain"`
	Selector      string `db:"selector" json:"selector"`
	Result        string `db:"result" json:"result"`
	Comment       string `db:"comment" json:"comment,omitempty"`
	Authority     string `db:"authority" json:"authority,omitempty"`
	AuthorityURI  string `db:"authority_uri" json:"authority_uri,omitempty"`
	IndicatorURI  string `db:"indicator_uri" json:"indicator_uri,omitempty"`
	IndicatorHash string `db:"indicator_hash" json:"indicator_hash,omitempty"`
	HasIndicator  int    `db:"has_indicator" json:"has_indicator"`
	// Matched is MatchYes, MatchNo or MatchUnknown. Note that the zero value
	// is MatchNo, so a caller that cannot perform the comparison must set
	// MatchUnknown explicitly: "we could not check" and "the hashes differ"
	// are different findings and must not collapse into one.
	Matched int    `db:"matched" json:"matched"`
	RawAR   string `db:"raw_ar" json:"raw_ar,omitempty"`
}

// Values for BIMIVerdict.Matched.
const (
	MatchNo      = 0
	MatchYes     = 1
	MatchUnknown = -1
)

// MatchLabel renders the tri-state for the UI.
func (v BIMIVerdict) MatchLabel() string {
	switch v.Matched {
	case MatchYes:
		return "matches the logo you serve"
	case MatchNo:
		return "differs from the logo you serve"
	}
	return "not compared"
}

// Displayed reports a verdict that would have shown a logo.
func (v BIMIVerdict) Displayed() bool { return v.Result == "pass" }

// SaveBIMIVerdict stores one verdict, ignoring a message and receiver already
// recorded.
//
// Seed mailboxes are read repeatedly and the same message is seen again on
// every pass, so re-recording has to be free of consequence. Returns whether
// the row was new.
func SaveBIMIVerdict(db *sqlx.DB, v BIMIVerdict) (bool, error) {
	v.FromDomain = strings.ToLower(strings.TrimSpace(v.FromDomain))
	v.Receiver = strings.ToLower(strings.TrimSpace(v.Receiver))
	v.Selector = strings.ToLower(strings.TrimSpace(v.Selector))
	if v.Matched < MatchUnknown || v.Matched > MatchYes {
		v.Matched = MatchUnknown
	}
	res, err := db.Exec(`
		INSERT INTO bimi_verdicts
			(account_id, message_id, at, receiver, from_domain, selector, result, comment,
			 authority, authority_uri, indicator_uri, indicator_hash, has_indicator, matched, raw_ar)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(message_id, receiver) DO NOTHING`,
		v.AccountID, v.MessageID, v.At, v.Receiver, v.FromDomain, v.Selector, v.Result, v.Comment,
		v.Authority, v.AuthorityURI, v.IndicatorURI, v.IndicatorHash, v.HasIndicator, v.Matched, v.RawAR)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListBIMIVerdicts returns verdicts newest first, optionally for one domain.
func ListBIMIVerdicts(db *sqlx.DB, domain string, since int64, limit int) ([]BIMIVerdict, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT * FROM bimi_verdicts WHERE 1=1`
	var args []any
	if domain != "" {
		query += ` AND from_domain = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(domain)))
	}
	if since > 0 {
		query += ` AND at >= ?`
		args = append(args, since)
	}
	query += ` ORDER BY at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	out := []BIMIVerdict{}
	err := db.Select(&out, query, args...)
	return out, err
}

// BIMIReceiverVerdict summarises one receiver's verdicts on one domain (B21).
type BIMIReceiverVerdict struct {
	Receiver   string `db:"receiver" json:"receiver"`
	FromDomain string `db:"from_domain" json:"from_domain"`
	Selector   string `db:"selector" json:"selector"`
	Messages   int64  `db:"messages" json:"messages"`
	Passed     int64  `db:"passed" json:"passed"`
	FirstSeen  int64  `db:"first_seen" json:"first_seen"`
	LastSeen   int64  `db:"last_seen" json:"last_seen"`
	// LastResult is the most recent verdict, which is the one that matters:
	// a receiver that passed for a month and fails today is a regression.
	LastResult  string  `db:"last_result" json:"last_result"`
	LastComment string  `db:"last_comment" json:"last_comment,omitempty"`
	PassRate    float64 `db:"-" json:"pass_rate"`
}

// SummariseBIMIVerdicts groups verdicts by receiver, domain and selector.
func SummariseBIMIVerdicts(db *sqlx.DB, domain string, since int64) ([]BIMIReceiverVerdict, error) {
	query := `
		SELECT receiver, from_domain, selector,
		       COUNT(*) AS messages,
		       COALESCE(SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END), 0) AS passed,
		       MIN(at) AS first_seen,
		       MAX(at) AS last_seen,
		       (SELECT v2.result FROM bimi_verdicts v2
		         WHERE v2.receiver = v.receiver AND v2.from_domain = v.from_domain
		           AND v2.selector = v.selector
		         ORDER BY v2.at DESC, v2.id DESC LIMIT 1) AS last_result,
		       (SELECT v2.comment FROM bimi_verdicts v2
		         WHERE v2.receiver = v.receiver AND v2.from_domain = v.from_domain
		           AND v2.selector = v.selector
		         ORDER BY v2.at DESC, v2.id DESC LIMIT 1) AS last_comment
		  FROM bimi_verdicts v WHERE 1=1`
	var args []any
	if domain != "" {
		query += ` AND from_domain = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(domain)))
	}
	if since > 0 {
		query += ` AND at >= ?`
		args = append(args, since)
	}
	query += ` GROUP BY receiver, from_domain, selector ORDER BY from_domain, receiver`

	out := []BIMIReceiverVerdict{}
	if err := db.Select(&out, query, args...); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Messages > 0 {
			out[i].PassRate = float64(out[i].Passed) / float64(out[i].Messages) * 100
		}
	}
	return out, nil
}

// BIMIVerdictRegression is a receiver that used to show a logo and no longer
// does (X30).
type BIMIVerdictRegression struct {
	Receiver   string `json:"receiver"`
	FromDomain string `json:"from_domain"`
	Selector   string `json:"selector"`
	// LastPass is when the receiver last stamped bimi=pass.
	LastPass int64 `json:"last_pass"`
	// Result and Comment are what it says now.
	Result  string `json:"result"`
	Comment string `json:"comment,omitempty"`
	At      int64  `json:"at"`
	// SinceFailures counts the non-passing verdicts since the last pass.
	SinceFailures int64 `json:"since_failures"`
}

// FindBIMIVerdictRegressions returns receivers whose most recent verdict is
// not a pass but which have passed before, with the change falling at or after
// since.
//
// The "has passed before" condition is what makes this a regression rather
// than a complaint: a receiver that has never shown the logo is telling the
// operator something, but it is not telling them that something broke.
func FindBIMIVerdictRegressions(db *sqlx.DB, since int64) ([]BIMIVerdictRegression, error) {
	type row struct {
		Receiver   string `db:"receiver"`
		FromDomain string `db:"from_domain"`
		Selector   string `db:"selector"`
		LastPass   int64  `db:"last_pass"`
		Result     string `db:"result"`
		Comment    string `db:"comment"`
		At         int64  `db:"at"`
		Failures   int64  `db:"failures"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT g.receiver, g.from_domain, g.selector, g.last_pass,
		       cur.result, cur.comment, cur.at,
		       (SELECT COUNT(*) FROM bimi_verdicts f
		         WHERE f.receiver = g.receiver AND f.from_domain = g.from_domain
		           AND f.selector = g.selector AND f.at > g.last_pass AND f.result != 'pass') AS failures
		  FROM (
			SELECT receiver, from_domain, selector,
			       MAX(CASE WHEN result = 'pass' THEN at END) AS last_pass,
			       MAX(at) AS newest
			  FROM bimi_verdicts
			 GROUP BY receiver, from_domain, selector
		  ) g
		  JOIN bimi_verdicts cur
		    ON cur.receiver = g.receiver AND cur.from_domain = g.from_domain
		   AND cur.selector = g.selector AND cur.at = g.newest
		 WHERE g.last_pass IS NOT NULL
		   AND cur.result != 'pass'
		   AND cur.at >= ?
		 ORDER BY cur.at DESC`, since); err != nil {
		return nil, err
	}
	out := make([]BIMIVerdictRegression, 0, len(rows))
	for _, r := range rows {
		out = append(out, BIMIVerdictRegression{
			Receiver: r.Receiver, FromDomain: r.FromDomain, Selector: r.Selector,
			LastPass: r.LastPass, Result: r.Result, Comment: r.Comment,
			At: r.At, SinceFailures: r.Failures,
		})
	}
	return out, nil
}

// CountSeedAccounts returns how many enabled seed mailboxes are configured,
// which is what the UI uses to decide whether B21 is worth showing at all.
func CountSeedAccounts(db *sqlx.DB) (int, error) {
	var n int
	err := db.Get(&n, `SELECT COUNT(*) FROM accounts WHERE enabled = 1 AND purpose = ?`, PurposeSeed)
	return n, err
}

// LatestSeedVerdictAt returns when the newest verdict was recorded, or 0.
func LatestSeedVerdictAt(db *sqlx.DB) (int64, error) {
	var at *int64
	if err := db.Get(&at, `SELECT MAX(at) FROM bimi_verdicts`); err != nil {
		return 0, err
	}
	if at == nil {
		return 0, nil
	}
	return *at, nil
}

// VerdictAge renders how long ago a verdict was seen, for log lines.
func VerdictAge(at int64) string {
	if at == 0 {
		return "never"
	}
	return time.Since(time.Unix(at, 0)).Round(time.Hour).String()
}

// RecordSeedVerdicts extracts and stores the bimi= verdicts in one seed
// message's headers, returning how many were new. receivedAt is the time the
// *server* recorded for the message (IMAP INTERNALDATE, Graph
// receivedDateTime); 0 when it is unknown.
//
// The message itself is not stored. What is kept is the verdict, the domain it
// was about and the Authentication-Results segment it came from — enough to
// show what a receiver concluded, and no more of the operator's mail than that.
//
// # Trust
//
// An Authentication-Results header is not evidence by itself. RFC 8601 §7.1 is
// explicit that it is only trustworthy when added by the receiving ADMD's own
// border MTA, which is expected to strip or rename any arriving header bearing
// its authserv-id. Anyone who can send mail to the seed address can put
// whatever they like in the ones below it.
//
// Two consequences follow, and both are enforced here:
//
//   - Only the topmost header is recorded. The receiving MTA prepends its own,
//     so a header forged by a sender sits beneath it. Without this an attacker
//     could invent verdicts for any domain and any receiver by choosing the
//     header.d and authserv-id values themselves.
//   - The timestamp is the server's, not the message's. The Date header is
//     attacker-controlled, and X30 asks which verdict is *newest*: a forged
//     header dated a year ahead would otherwise become the newest verdict for
//     that receiver for ever, permanently masking a real regression.
//
// Residual risk: a provider that does not strip inbound headers bearing its
// own authserv-id would let a forged header arrive on top. Nothing this
// application can see distinguishes that case, which is why B21 is presented
// as what receivers *said*, next to the checks that do not depend on anyone's
// good behaviour.
func RecordSeedVerdicts(db *sqlx.DB, accountID int64, header mail.Header, receivedAt int64) (int, error) {
	all := header["Authentication-Results"]
	if len(all) == 0 {
		return 0, nil
	}
	verdicts := bimi.ParseAuthResults(all[:1])
	if len(verdicts) == 0 {
		return 0, nil
	}

	messageID := strings.Trim(strings.TrimSpace(header.Get("Message-Id")), "<>")
	now := time.Now().Unix()
	at := receivedAt
	if at <= 0 {
		// No server time: fall back to the Date header, but never let it claim
		// to be from the future.
		if t, err := header.Date(); err == nil {
			at = t.Unix()
		}
		if at > now {
			at = now
		}
	}
	if at <= 0 {
		at = now
	}
	fromDomain := addressDomain(header.Get("From"))
	hasIndicator := 0
	if strings.TrimSpace(header.Get("Bimi-Indicator")) != "" {
		hasIndicator = 1
	}

	saved := 0
	for _, v := range verdicts {
		domain := v.HeaderD
		if domain == "" {
			domain = fromDomain
		}
		selector := v.Selector
		if selector == "" {
			selector = bimi.DefaultSelector
		}

		row := BIMIVerdict{
			AccountID: accountID, MessageID: messageID, At: at,
			Receiver: v.Receiver, FromDomain: domain, Selector: selector,
			Result: v.Result, Comment: v.Comment,
			Authority: v.Authority, AuthorityURI: v.AuthorityURI,
			IndicatorURI: v.IndicatorURI, IndicatorHash: v.IndicatorHash,
			HasIndicator: hasIndicator,
			Matched:      matchIndicatorHash(db, domain, selector, v),
			RawAR:        v.Raw,
		}
		// A message with no Message-ID cannot be deduplicated, so it is keyed
		// by what it does have. Two such messages from one receiver in the
		// same second would collapse; that is better than recording the same
		// message on every pass for ever.
		if row.MessageID == "" {
			row.MessageID = fmt.Sprintf("no-message-id/%s/%d", domain, at)
		}
		ok, err := SaveBIMIVerdict(db, row)
		if err != nil {
			return saved, err
		}
		if ok {
			saved++
		}
	}
	return saved, nil
}

// matchIndicatorHash compares the truncated hash a receiver recorded against
// the logo this application retrieved for the same domain and selector.
//
// Returns -1 when there is nothing to compare — no hash from the receiver, or
// no retrieved logo of our own. "We could not check" must not be stored as
// "the hashes differ", which would turn an unchecked message into a fault.
func matchIndicatorHash(db *sqlx.DB, domain, selector string, v bimi.Verdict) int {
	if v.IndicatorHash == "" {
		return MatchUnknown
	}
	snap, err := GetCurrentBIMISnapshot(db, domain, selector, BIMISnapshotIndicator)
	if err != nil || snap == nil || snap.Content == "" {
		return MatchUnknown
	}
	if v.HashMatches(snap.Content) {
		return MatchYes
	}
	return MatchNo
}

// addressDomain returns the domain of the first address in a header value.
func addressDomain(value string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil {
		// Fall back to whatever follows the last "@": a From header that will
		// not parse is still usually readable enough to name a domain.
		if _, host, ok := strings.Cut(value, "@"); ok {
			return strings.ToLower(strings.Trim(strings.TrimSpace(host), "<>\""))
		}
		return ""
	}
	_, host, _ := strings.Cut(addr.Address, "@")
	return strings.ToLower(host)
}
