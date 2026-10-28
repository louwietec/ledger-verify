package cli

// The vectors of condition (7) as the second way to level 3 (format spec
// 10.9.1, 10.9.4, 10.9.5) whose expectation lies in members that the
// expected files do not carry (registry testvectors.evidence, "why"):
// evidence_level.qualified_time and next (10.10.2), and in the text report
// the line "qualifiziert bestätigt" and the one line for (4) or (7)
// (10.10.3). The run is the one of the audit environment of the vector, as
// in TestKorpusMitPruefumgebung.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// qtSoll is what the member why of a vector says: qualified_time and next
// as JSON (JCS), and lines the German text report holds ("" none).
type qtSoll struct {
	qualifiedTime string
	next          string
	line          string
}

// Both reasons in one line for (4) or (7) (10.10.3), at the place of (4).
const zeileViererSieben = "    - Zeitzeuge einer vom Prüfer als qualifiziert benannten Stelle, dessen Token sich als qualifiziert ausweist oder Gegensignaturen in Tagen des Herstellerprotokolls nachgewiesen, deren Eintrag den Zeitstempel einer vom Prüfer als qualifiziert benannten Stelle trägt, der sich als qualifiziert ausweist, höchstens 36 Stunden nach der Gegensignatur (7.4.6): kein Zeitzeuge in der Kette; "

var qtSollwerte = map[string]qtSoll{
	"evidence_level_3_both_ways": {
		qualifiedTime: `{"gap_ms":600000,"latest":"2026-01-03T00:05:01.000Z","tree_size":6,"via":"log_day_qualified"}`,
		next:          `null`,
		line:          "  qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitstempel des Herstellerprotokolls, tree_size 6, 0 Std. 10 Min. nach der Gegensignatur)",
	},
	"evidence_level_3_log_day_qualified": {
		qualifiedTime: `{"gap_ms":600000,"latest":"2026-01-03T00:05:01.000Z","tree_size":5,"via":"log_day_qualified"}`,
		next:          `null`,
		line:          "  qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitstempel des Herstellerprotokolls, tree_size 5, 0 Std. 10 Min. nach der Gegensignatur)",
	},
	"evidence_log_stamp_gap_exact": {
		qualifiedTime: `{"gap_ms":129600000,"latest":"2026-01-04T11:55:01.000Z","tree_size":5,"via":"log_day_qualified"}`,
		next:          `null`,
		line:          "  qualifiziert bestätigt: spätestens 2026-01-04T11:55:01.000Z (Zeitstempel des Herstellerprotokolls, tree_size 5, 36 Std. 0 Min. nach der Gegensignatur)",
	},
	"evidence_log_stamp_gap_truncated": {
		qualifiedTime: `{"gap_ms":129600000,"latest":"2026-01-04T11:55:01.000Z","tree_size":5,"via":"log_day_qualified"}`,
		next:          `null`,
		line:          "  qualifiziert bestätigt: spätestens 2026-01-04T11:55:01.000Z (Zeitstempel des Herstellerprotokolls, tree_size 5, 36 Std. 0 Min. nach der Gegensignatur)",
	},
	"evidence_log_stamp_gap_exceeded": {
		qualifiedTime: `null`,
		next:          `{"level":3,"missing":["time_witness_qualified","log_day_qualified"],"need":"all"}`,
		line:          zeileViererSieben + "der Zeitstempel der als qualifiziert benannten Stelle liegt mehr als 36 Stunden nach der Gegensignatur (10.9.4)",
	},
	"evidence_qualified_log_root_log_only": {
		qualifiedTime: `null`,
		next:          `{"level":3,"missing":["time_witness_qualified","log_day_qualified"],"need":"all"}`,
		line:          zeileViererSieben + "keine Wurzel übergeben, die zugleich für Zeitstempel des Herstellerprotokolls übergeben und als qualifiziert benannt ist (--vendor-log-tsa-root und --tsa-qualified-roots)",
	},
	"evidence_qualified_log_root_qualified_only": {
		qualifiedTime: `null`,
		next:          `{"level":3,"missing":["time_witness_qualified","receipts_logged","log_day_qualified"],"need":"all"}`,
	},
	"evidence_qualified_time_tie": {
		qualifiedTime: `{"gap_ms":null,"latest":"2026-01-03T00:05:01.000Z","tree_size":10,"via":"time_witness_qualified"}`,
		next:          `null`,
		line:          "  qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitzeuge der Kette, tree_size 10)",
	},
}

func TestKorpusQualifizierterZeitpunkt(t *testing.T) {
	dir := vektor("")
	n := 0
	for name, s := range qtSollwerte {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			continue // the package is not there yet
		}
		env, err := os.ReadFile(filepath.Join(dir, "pruefer_"+name+".json"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		args, err := vfy.AuditEnvironmentArgs(env, dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		n++
		base := append([]string{"--now-from-package"}, args...)
		_, out, errOut := lauf(append(append([]string{"--json"}, base...), vektor(name))...)
		if out == "" {
			t.Errorf("%s: no report (%s)", name, strings.TrimSpace(errOut))
			continue
		}
		var r struct {
			Stats struct {
				EvidenceLevel map[string]json.RawMessage `json:"evidence_level"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for member, want := range map[string]string{"qualified_time": s.qualifiedTime, "next": s.next} {
			raw, ok := r.Stats.EvidenceLevel[member]
			if !ok {
				t.Errorf("%s: no member evidence_level.%s", name, member)
				continue
			}
			v, err := jcs.Parse(raw)
			if err != nil {
				t.Fatalf("%s: %s: %v", name, member, err)
			}
			if got := string(jcs.Canon(v)); got != want {
				t.Errorf("%s: evidence_level.%s = %s, want %s", name, member, got, want)
			}
		}
		_, text, _ := lauf(append(append([]string{"--lang", "de"}, base...), vektor(name))...)
		hasLine := strings.Contains(text, "\n  qualifiziert bestätigt: ")
		if hasLine != (s.qualifiedTime != "null") {
			t.Errorf("%s: line qualifiziert bestätigt present %v with qualified_time %s (10.10.3)", name, hasLine, s.qualifiedTime)
		}
		if s.line != "" && !strings.Contains(text, "\n"+s.line+"\n") {
			t.Errorf("%s: the text report lacks the line %q (10.10.3)", name, s.line)
		}
	}
	t.Logf("%d vectors of condition (7)", n)
}
