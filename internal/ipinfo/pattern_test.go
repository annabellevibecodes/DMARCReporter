package ipinfo

import "testing"

func TestClassifySourcePattern(t *testing.T) {
	th := DefaultPatternThresholds
	cases := []struct {
		name string
		m    Matrix
		want string
	}{
		{"empty", Matrix{}, PatternMixed},
		{"healthy", Matrix{BothPass: 95, Neither: 5}, PatternHealthy},
		{"forwarder", Matrix{DKIMOnly: 70, BothPass: 30}, PatternForwarder},
		{"broken", Matrix{SPFOnly: 61, BothPass: 39}, PatternBrokenSigning},
		{"spoof", Matrix{Neither: 100}, PatternSpoofSuspect},
		{"spoof-too-few", Matrix{Neither: 4}, PatternMixed},
		{"mixed", Matrix{BothPass: 50, Neither: 50}, PatternMixed},
	}
	for _, c := range cases {
		if got := ClassifySourcePattern(c.m, th); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if got := EffectivePattern(Matrix{Neither: 100}, "known_good", th); got != PatternHealthy {
		t.Errorf("override known_good: got %s", got)
	}
	if got := EffectivePattern(Matrix{Neither: 100}, "unknown", th); got != PatternSpoofSuspect {
		t.Errorf("override unknown should not override: got %s", got)
	}
}
