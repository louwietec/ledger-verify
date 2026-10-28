package wasmapi

// Die zwei Zeilen unter dem Urteil (Formatspezifikation 10.10.3, Absatz
// "Browser-Fassung"): die Stufe mit Reichweite und der Status der
// Verbundenheit. Die Farbe des Urteils bleibt an den Exit-Code gebunden; die
// Zeilen sind kein Teil des Urteils und aendern es nicht (10.9, 10.10).
//
// WOHER DIE TEXTE KOMMEN. Beide Zeilen stehen in der Registry, und die
// Kommandozeile gibt sie aus ihren Tabellen in internal/vfy aus. Diese
// Tabellen sind nicht exportiert; deshalb traegt diese Datei die wenigen
// Wendungen der ersten Zeile als Abschrift, und wasmapi_test.go haelt jede
// davon Zeichen fuer Zeichen gegen spec/registry.json. Die Zeile zur
// Verbundenheit schreibt diese Datei nicht selbst: sie nimmt die Zeile, die
// der Textbericht als letzte Zeile des Blocks der Beweisstufe ausgibt, also
// dieselbe Zeile, die ledger-verify druckt. Eine eigene Fassung des Satzes
// mit Grundlagen, Zeitraeumen und Schluesselquelle waere eine dritte
// Handkopie.
// / The two lines under the verdict (format spec 10.10.3). The first is
// built from registry texts copied here and held against the registry by the
// test; the second is the affiliation line of the text report itself.

import (
	"strconv"
	"strings"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// zeilenTexte are the registry texts of the first line, keyed by language
// and by their place in the registry (zeilenQuelle in wasmapi_test.go):
//
//	browser, head_level0, state_line, label, label_chain:
//	    verifier.evidence_level.texts.<key>.<lang>
//	level0_name: verifier.evidence_level.levels.0.name_<lang>
//	state.<state>: verifier.evidence_level.states.<state>.<lang>
//	affiliation_prefix: the common start of every text of
//	    verifier.affiliation.texts that opens the line on affiliation
var zeilenTexte = map[string]map[string]string{
	"de": {
		"browser":             "Beweisstufe: {level} von 3, belegt bis seq {up_to_tree_size} von {entries}",
		"head_level0":         "{label} 0 von 3 ({name}), seq 1 bis {entries}.",
		"state_line":          "{label} {state}",
		"label":               "Beweisstufe:",
		"label_chain":         "Beweisstufe der Kette:",
		"level0_name":         "Selbstauskunft",
		"state.chain_invalid": "keine (Kette ungültig)",
		"state.format_error":  "nicht bestimmt (Formatfehler)",
		"affiliation_prefix":  "Verbundenheit mit dem Hersteller:",
	},
	"en": {
		"browser":             "Evidence level: {level} of 3, evidenced up to seq {up_to_tree_size} of {entries}",
		"head_level0":         "{label} 0 of 3 ({name}), seq 1 to {entries}.",
		"state_line":          "{label} {state}",
		"label":               "Evidence level:",
		"label_chain":         "Evidence level of the chain:",
		"level0_name":         "self-statement",
		"state.chain_invalid": "none (chain invalid)",
		"state.format_error":  "not determined (format error)",
		"affiliation_prefix":  "Affiliation with the vendor:",
	},
}

// fehlt marks a text that is not there, visibly, like the tables of
// internal/vfy (never a silent fall back to the other language).
func fehlt(key string) string { return "⟪MISSING:" + key + "⟫" }

func zeilenText(lang, key string) string {
	if s, ok := zeilenTexte[lang][key]; ok {
		return s
	}
	return fehlt(key)
}

// fuellen replaces the placeholders {name} of a registry text.
func fuellen(s string, kv ...string) string {
	for i := 0; i+1 < len(kv); i += 2 {
		s = strings.ReplaceAll(s, "{"+kv[i]+"}", kv[i+1])
	}
	return s
}

// noteMaterial is the note of an evidence level whose exit-2 findings all
// come from material_classes (registry verifier.evidence_level.note_occasions):
// the head line then begins with label_chain (10.10.3).
const noteMaterial = "material_contradiction"

// beweisstufenZeile is the first line under the verdict (10.10.3,
// "Browser-Fassung"), for example "Beweisstufe: 2 von 3, belegt bis seq 309
// von 311" (registry verifier.evidence_level.texts.browser).
//
// Where the registry has no browser text of its own, the line is the text
// the command line prints in the head of its block: at level 0 head_level0
// ("Beweisstufe: 0 von 3 (Selbstauskunft), seq 1 bis <N>."), because level 0
// evidences nothing beyond the chain itself and "belegt bis" would read as
// if it did; in the states chain_invalid and format_error the state line
// ("Beweisstufe: keine (Kette ungültig)"). When every exit-2 finding comes
// from material_classes, the line begins with "Beweisstufe der Kette:" like
// the head line of the text block (10.10.3).
func beweisstufenZeile(ev *vfy.EvidenceLevelStat, lang string) string {
	if ev == nil {
		return fehlt("evidence_level")
	}
	label := zeilenText(lang, "label")
	if ev.State != "rated" || ev.Level == nil {
		return fuellen(zeilenText(lang, "state_line"), "label", label, "state", zeilenText(lang, "state."+ev.State))
	}
	material := false
	for _, n := range ev.Notes {
		material = material || n == noteMaterial
	}
	entries := "?"
	if ev.Entries != nil {
		entries = strconv.FormatInt(*ev.Entries, 10)
	}
	if *ev.Level == 0 {
		if material {
			label = zeilenText(lang, "label_chain")
		}
		return fuellen(zeilenText(lang, "head_level0"), "label", label, "name", zeilenText(lang, "level0_name"), "entries", entries)
	}
	upTo := "?"
	if ev.UpToTreeSize != nil {
		upTo = strconv.FormatInt(*ev.UpToTreeSize, 10)
	}
	s := fuellen(zeilenText(lang, "browser"), "level", strconv.Itoa(*ev.Level), "up_to_tree_size", upTo, "entries", entries)
	if material && strings.HasPrefix(s, label) {
		s = zeilenText(lang, "label_chain") + strings.TrimPrefix(s, label)
	}
	return s
}

// verbundenheitsZeile is the second line under the verdict: the line on
// affiliation (registry verifier.affiliation.texts) exactly as the text
// report prints it, the last line of the block of the evidence level
// (10.10.3), without its indentation. The block begins at the first line
// that starts with the label of the evidence level; its follow-up lines are
// indented by two spaces. A report without that line gives a visible marker,
// never an empty line (wasmapi_test.go: never on the corpus).
func verbundenheitsZeile(bericht, lang string) string {
	label, labelKette := zeilenText(lang, "label"), zeilenText(lang, "label_chain")
	zeilen := strings.Split(bericht, "\n")
	for i, z := range zeilen {
		if !strings.HasPrefix(z, label) && !strings.HasPrefix(z, labelKette) {
			continue
		}
		letzte := ""
		for _, f := range zeilen[i+1:] {
			if !strings.HasPrefix(f, "  ") {
				break
			}
			letzte = strings.TrimPrefix(f, "  ")
		}
		if strings.HasPrefix(letzte, zeilenText(lang, "affiliation_prefix")) {
			return letzte
		}
		break
	}
	return fehlt("affiliation line")
}
