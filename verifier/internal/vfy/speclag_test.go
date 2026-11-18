package vfy

// Since the decisions of 26.10. the text of the specification is ahead of
// spec/registry.json in a few places: condition (7) as the second way to
// level 3 with the reason qualified_day_stamp_gap (format spec 10.9.1,
// 10.9.4, 10.9.5), the texts of level 3 and of condition (7) (10.9.8) and
// the 24 months of former_relation (heartbeat spec 9.10). The mirror tests
// hold the hand-copied lists and texts against the registry; where the
// registry has not caught up with the specification yet, they hold them
// against the text of the specification itself, since the specification
// wins over the registry. Once the registry carries the new text, the
// comparison with the registry decides again.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// specFile reads spec/<name>.
func specFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// specRowEnds reports whether a table row of doc starts with prefix and has
// text as its last cell.
func specRowEnds(doc, prefix, text string) bool {
	for _, l := range strings.Split(doc, "\n") {
		if strings.HasPrefix(l, prefix) && strings.HasSuffix(l, " | "+text+" |") {
			return true
		}
	}
	return false
}

// specAheadText reports whether key is one of the texts the specification
// gives newer than the registry and both tables carry it exactly as the
// specification writes it, in German and in English.
func specAheadText(t *testing.T, key string) bool {
	t.Helper()
	de, en := tableDE[key], tableEN[key]
	if de == "" || en == "" {
		return false
	}
	switch key {
	case "ev.cond.log_day_qualified": // 10.9.8, "Bezeichnungen der Bedingungen im Bericht"
		return strings.Contains(specFile(t, "format.de.md"), "(7) „"+de+"“") && strings.Contains(specFile(t, "format.en.md"), "(7) \""+en+"\"")
	case "ev.level.3.text": // 10.9.8, table of the levels
		return specRowEnds(specFile(t, "format.de.md"), "| 3 | verankert und abgeglichen |", de) &&
			specRowEnds(specFile(t, "format.en.md"), "| 3 | anchored and reconciled |", en)
	case "ev.reason." + rsDayStampGap: // 10.9.4, table "Gründe"
		return specRowEnds(specFile(t, "format.de.md"), "| `"+rsDayStampGap+"` |", de) &&
			specRowEnds(specFile(t, "format.en.md"), "| `"+rsDayStampGap+"` |", en)
	case "aff.basis.former_relation": // heartbeat spec 9.10, table of the bases
		return specRowEnds(specFile(t, "heartbeat.de.md"), "| `former_relation` |", de) &&
			specRowEnds(specFile(t, "heartbeat.en.md"), "| `former_relation` |", en)
	}
	return false
}

// specSection returns the lines of doc from the heading that starts with
// head up to the next heading of the same or a higher level.
func specSection(t *testing.T, doc, head string) []string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, head) {
			continue
		}
		depth := len(l) - len(strings.TrimLeft(l, "#"))
		for j := i + 1; j < len(lines); j++ {
			if d := len(lines[j]) - len(strings.TrimLeft(lines[j], "#")); d > 0 && d <= depth && strings.HasPrefix(lines[j][d:], " ") {
				return lines[i:j]
			}
		}
		return lines[i:]
	}
	t.Fatalf("no section %q", head)
	return nil
}

var reReasonRow = regexp.MustCompile("^\\| `([a-z0-9_]+)` \\| \\([1-7]\\)")

// specReasonOrder is the order of the codes in the table "Gründe" of format
// spec 10.9.4 (format.de.md).
func specReasonOrder(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, l := range specSection(t, specFile(t, "format.de.md"), "#### 10.9.4") {
		if m := reReasonRow.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

var reStageHead = regexp.MustCompile("^`([a-z0-9_]+)`")

// specStages are the stages of a condition in the table of format spec
// 10.9.4 (format.de.md, column "Stufen je Gegenstand, in dieser
// Reihenfolge"): the code at the head of each item, items separated by
// "; " outside parentheses; nil for "keine" or "je Quittung (unten)".
func specStages(t *testing.T, code string) []string {
	t.Helper()
	for _, l := range specSection(t, specFile(t, "format.de.md"), "#### 10.9.4") {
		if !strings.HasPrefix(l, "| (") || !strings.Contains(l, "`"+code+"`") {
			continue
		}
		cells := strings.Split(l, " | ")
		if len(cells) < 4 || !strings.HasPrefix(cells[0], "| (") || !strings.Contains(cells[0], "`"+code+"`") {
			continue
		}
		var out []string
		depth, start := 0, 0
		cell := cells[3]
		for i := 0; i <= len(cell); i++ {
			if i < len(cell) {
				switch cell[i] {
				case '(':
					depth++
				case ')':
					depth--
				}
			}
			if i == len(cell) || depth == 0 && strings.HasPrefix(cell[i:], "; ") {
				if m := reStageHead.FindStringSubmatch(strings.TrimSpace(cell[start:i])); m != nil {
					out = append(out, m[1])
				}
				start = i + 2
			}
		}
		return out
	}
	t.Fatalf("no row of condition %s in 10.9.4", code)
	return nil
}

// sameOrAhead holds a hand-copied list against the registry, or, where the
// registry lags the specification, against the list of the specification.
func sameOrAhead(t *testing.T, what string, code, reg, spec []string) {
	t.Helper()
	c, r := strings.Join(code, ","), strings.Join(reg, ",")
	switch {
	case c == r:
	case spec != nil && c == strings.Join(spec, ","):
		t.Logf("%s: the registry %v lags the specification %v", what, reg, spec)
	default:
		t.Errorf("%s: %v, registry %v, specification %v", what, code, reg, spec)
	}
}

// TestSpecAheadHelpers: the helpers read the tables of the specification
// as they stand: the reasons of 10.9.4 end with qualified_day_stamp_late
// and qualified_day_stamp_gap, the stages of (7) and (4) are those of the
// table, and every text the specification gives newer than the registry
// stands there in both languages.
func TestSpecAheadHelpers(t *testing.T) {
	order := specReasonOrder(t)
	if strings.Join(order, ",") != strings.Join(evReasonOrder, ",") {
		t.Errorf("10.9.4 reasons %v, code %v", order, evReasonOrder)
	}
	for _, code := range []string{CondTimeWitness, CondTimeWitnessQualified, CondReceiptKeyConfirmed, CondLogDayQualified} {
		if got := specStages(t, code); strings.Join(got, ",") != strings.Join(evStages[code], ",") {
			t.Errorf("10.9.4 stages of %s: %v, code %v", code, got, evStages[code])
		}
	}
	for _, key := range []string{"ev.cond.log_day_qualified", "ev.level.3.text", "ev.reason." + rsDayStampGap, "aff.basis.former_relation"} {
		if !specAheadText(t, key) {
			t.Errorf("%s: %q / %q do not stand in the specification", key, tableDE[key], tableEN[key])
		}
	}
	if specAheadText(t, "ev.cond.time_witness") {
		t.Error("a text outside the list counts as ahead")
	}
}
