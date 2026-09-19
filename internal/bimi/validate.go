package bimi

import (
	"context"
	"time"
)

// Validation is the active half of the checks — B6 to B9 — for one published
// record: what the indicator endpoint served, what the evidence document says,
// and whether the two agree.
//
// Agreement is derived from the other two rather than stored: it is a
// comparison of two hashes, and a derived field kept beside its inputs is a
// field that can contradict them.
type Validation struct {
	Indicator *IndicatorResult `json:"indicator,omitempty"`
	Evidence  *EvidenceResult  `json:"evidence,omitempty"`
	Agreement AgreementResult  `json:"agreement"`
	CheckedAt int64            `json:"checked_at,omitempty"`
}

// Validate retrieves and checks the documents one record names.
//
// A record that declines to publish, or that is not usable in the first place,
// is not fetched: there is nothing to retrieve, and asking anyway would make
// outbound requests on behalf of a record no receiver would act on.
func Validate(ctx context.Context, f *Fetcher, rec Record, opts EvidenceOptions) Validation {
	out := Validation{CheckedAt: time.Now().Unix()}
	if rec.State() != StatePublished || rec.Location == "" {
		out.Agreement = AgreementResult{Note: "the record publishes no indicator to check"}
		return out
	}

	ind := FetchIndicator(ctx, f, rec.Location)
	out.Indicator = &ind

	if rec.Authority != "" {
		ev := FetchEvidence(ctx, f, rec.Authority, opts)
		out.Evidence = &ev
	}
	out.Agreement = CompareMarks(out.Indicator, out.Evidence)
	return out
}

// Findings is every finding the active checks produced, indicator first, then
// evidence, then the agreement between them.
func (v Validation) Findings() []Finding {
	var out []Finding
	if v.Indicator != nil {
		out = append(out, v.Indicator.Findings...)
	}
	if v.Evidence != nil {
		out = append(out, v.Evidence.Findings...)
	}
	if f, ok := v.Agreement.Finding(); ok {
		out = append(out, f)
	}
	return out
}

// Valid reports whether the active checks found nothing disqualifying. A
// validation that was never performed is not valid — it is unknown, which
// callers distinguish by checking Indicator for nil.
func (v Validation) Valid() bool {
	if v.Indicator == nil {
		return false
	}
	for _, f := range v.Findings() {
		if f.Severity == SeverityError {
			return false
		}
	}
	return true
}

// FirstError returns the message of the first disqualifying finding, for the
// snapshot's error column and for a one-line summary.
func (v Validation) FirstError() string {
	for _, f := range v.Findings() {
		if f.Severity == SeverityError {
			return f.Message
		}
	}
	return ""
}
