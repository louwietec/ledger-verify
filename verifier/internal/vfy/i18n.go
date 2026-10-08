package vfy

import "sort"

// Built-in i18n string tables. Both tables MUST have identical key sets;
// a test enforces this. A missing key renders as a visible marker instead
// of silently falling back.
//
// Product name (A4): the report title names the product LEDGER and the tool
// ledger-verify — never the former product name "Rekorder". That also holds
// for the compatibility binary rekorder-verify, which renders these very
// tables. verifier/internal/cli/cli_test.go enforces it over real reports.

const missingOpen = "⟪" + "MISSING:" // ⟪MISSING:key⟫
const missingClose = "⟫"

type i18nTable map[string]string

// get returns the string for key or a visible MISSING marker.
func (t i18nTable) get(key string) string {
	if s, ok := t[key]; ok {
		return s
	}
	return missingOpen + key + missingClose
}

// missingKeys returns keys present in a but absent in b, sorted.
func missingKeys(a, b i18nTable) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func tableFor(lang string) i18nTable {
	if lang == "de" {
		return tableDE
	}
	return tableEN
}

var tableEN = i18nTable{
	"report.title":                 "LEDGER — verification report (ledger-verify)",
	"report.package":               "Package",
	"report.chain":                 "Chain",
	"report.spec":                  "Spec version",
	"report.created":               "Package created",
	"report.entries":               "Entries",
	"report.checkpoints":           "Checkpoints",
	"report.receipts":              "Receipts",
	"report.receipts_established":  "vendor key established by the auditor's trust anchor",
	"report.vendor_list":           "Vendor key list",
	"report.vendor_list_version":   "version",
	"report.vendor_list_issued":    "issued",
	"report.vendor_list_root":      "root",
	"report.time_anchors":          "Time witnesses",
	"report.time_anchors_verified": "independently established",
	"report.segments":              "Segments",
	"report.now":                   "Verification time (now)",
	"report.now_source.flag":       "given with --now",
	"report.now_source.package":    "taken from the package's verify_args.json — chosen by the prover, not by this verifier",
	"report.now_source.system":     "system clock",
	"report.freshness":             "Freshness window",
	"report.result":                "Result",
	"report.exit":                  "Exit code",
	"report.findings":              "Findings",
	"report.no_findings":           "No findings.",
	"report.seq":                   "seq",
	"report.notes":                 "Notes",
	"report.first_ts":              "First entry",
	"report.last_ts":               "Last entry",
	"note.genesis_license":         "GENESIS (seq 1) was written under spec 1.7 or earlier and its license_id is not a licence commitment: up to spec 1.7 the licence key itself could stand there, and then every holder of this package knows it — have the vendor replace the key (spec 4.1). No effect on the result; the value is not printed.",
	"report.now_not_determined":    "not determined — verify_args.json unusable (see FORMAT_ERROR, spec 10.8)",
	"note.purpose":                 "This report is technical evidence and supports fulfilment of documentation duties; it does not itself decide any legal question.",

	// Chain end (spec 8.6). The %-verbs are filled by RenderText.
	"report.chain_end":                      "Chain end",
	"report.chain_end_sealed":               "properly sealed at %s (reason %s, seq %d)",
	"report.chain_end_incomplete":           "not sealed — last entry seq %d (%s) at %s",
	"report.chain_end_critical":             "a critical entry without its immediate checkpoint (spec 6.2)",
	"report.chain_end_not_judged":           "not judged (format error, spec 8.6)",
	"report.last_countersigned":             "Last countersignature",
	"report.last_countersigned_value":       "checkpoint seq %d, tree_size %d, server_ts %s",
	"report.last_countersigned_key":         "vendor key",
	"report.last_countersigned_established": "established by the auditor's trust anchor",
	"report.last_countersigned_unverified":  "NOT established by a trust anchor of the auditor",
	"report.last_countersigned_none":        "none in this package",
	"note.chain_end_incomplete":             "Chain end incomplete: all entries present were checked, but the package does not prove that nothing came after its last entry — an export from a running installation without an export seal, a crash and a truncation look alike offline (spec 8.6).",
	"note.chain_end_sealed":                 "Sealed shows how this package ends, not that it is the chain's most recent state: a chain cut off behind an earlier seal looks the same, and every export seal is such a point (spec 8.6, 11.2).",

	// Completeness (spec 8.6, from 1.9) and the measured residual window
	// (spec 11.2, from 1.9). The %-verbs are filled by RenderText.
	"report.completeness":                 "Completeness",
	"report.completeness_established":     "established up to tree_size %d by the expected root passed (spec 8.6)",
	"report.completeness_not_established": "not established — no root countersigned by the vendor passed and found (spec 8.6)",
	"note.completeness_not_established":   "Completeness: without a root countersigned by the vendor, no statement is possible about whether this package holds the whole chain up to the moment it was requested — sealed or not (spec 8.6, 11.2). A full statement needs the vendor's anchor history: fetch it for chain_id %s yourself (heartbeat spec 9.7) and re-run with every root in it recorded BEFORE this package was requested — at least the most recent countersigned one, never a later one: a root recorded later lies beyond the end of the package and would contradict even an honest one — as --expect-root <tree_size>:<merkle_root> (found if the root over exactly the first tree_size entries equals it) or --expect-root <merkle_root> (found if the root over any prefix equals it); in the browser: the expected-root field. If the package does not contain it, entries the vendor had countersigned are missing: MERKLE_INCONSISTENT.",
	"note.completeness_established":       "Completeness established up to tree_size %d by the expected root passed (spec 8.6): the package holds the chain as far as that root reaches. It says nothing about entries after tree_size %d — for that, pass every root of the vendor's anchor history recorded before this package was requested.",
	"report.residual_window":              "Residual window",
	"report.residual_window_value":        "%d entries (seq %d to %d) after tree_size %d, spanning %s",
	"report.residual_window_none":         "all %d entries (seq 1 to %d): no countersigned checkpoint in this package",
	"report.residual_window_beyond":       "beyond the anchoring cadence",
	"note.residual_window_measured":       "Residual window (spec 11.2): the %d entries after the last countersigned tree state (tree_size %d) — seq %d to %d, from %s to %s, %s — are not yet externally anchored; the key holder could rewrite them without trace. Anchor messages in the chain without a countersignature in this package: %d.",
	"note.residual_window_none":           "Residual window (spec 11.2): this package holds no countersigned checkpoint, so none of its %d entries (seq 1 to %d, the last at %s) is externally anchored by the vendor; the key holder could rewrite them without trace. Anchor messages in the chain without a countersignature in this package: %d.",
	"note.residual_window_beyond":         "The residual window exceeds the anchoring cadence (one anchor every 5 minutes, tolerance 450,000 ms). Possible causes: the licence lapsed (the vendor no longer countersigns), egress is switched off, the vendor was unreachable, or the export is old. What the vendor had countersigned by then shows only in the comparison with a root it countersigned (spec 8.6, see the note on completeness).",

	// Deletion holds active at the chain end (spec 4.24, 9.3).
	"report.legal_holds":               "Legal hold active",
	"report.legal_hold_value":          "%s: scope %s to %s, set at seq %d, reference %s",
	"report.legal_hold_scope_replaced": "scope replaced at seq %d",

	"exit.0": "valid, no findings",
	"exit.1": "valid with findings",
	"exit.2": "invalid",
	"exit.3": "format error",
	"exit.4": "incomplete: chain end not sealed",

	"class.SEQ_BREAK":              "sequence gap or jump",
	"class.HASH_MISMATCH":          "hash chain broken",
	"class.SIG_INVALID":            "checkpoint signature invalid",
	"class.MERKLE_INCONSISTENT":    "Merkle consistency between anchored roots violated",
	"class.RECEIPT_INVALID":        "vendor countersignature invalid",
	"class.TIME_ANCHOR_INVALID":    "time witness contradicts the checkpoint or is forged",
	"class.FORK_DETECTED":          "receipt matches no prefix history",
	"class.CLOCK_ANOMALY":          "time contradiction without a chained CLOCK_JUMP",
	"class.CONCEALED_SILENCE":      "mid-chain silence without covering GAP/RESTART",
	"class.HANDOVER_BROKEN":        "SEAL/RESUME handover broken",
	"class.MISSING_CHECKPOINT":     "critical entry without an immediately following checkpoint",
	"class.CONTENT_MISMATCH":       "presented plaintext contradicts commitment",
	"class.REPORT_MISMATCH":        "presented report not in the chain",
	"class.UNSEALED_END":           "chain ends without a seal: incomplete (section 8.6)",
	"class.COVERED_GAP":            "declared gap (GAP)",
	"class.COVERED_SOURCE_GAP":     "declared source gap",
	"class.RECONCILIATION_DELTA":   "reconciliation delta against provider figures",
	"class.CONTENT_DELETED":        "content deleted per retention, chain intact",
	"class.HOLD_VIOLATION":         "content deleted despite an active deletion hold (section 9.3)",
	"class.CLOCK_JUMP_NOTE":        "declared clock jump",
	"class.TRAILING_SILENCE":       "chain ends before the freshness window",
	"class.NO_ANCHOR":              "no external anchor present",
	"class.TIME_ANCHOR_UNVERIFIED": "time witness present, its authority not independently established",
	"class.RECEIPT_UNVERIFIED":     "vendor countersignature consistent, but its key is not established by a trust anchor of the auditor",
	"class.SPEC_NEWER":             "package uses a newer minor version of the specification than the verifier",
	"class.UNKNOWN_ENTRY_TYPE":     "entry type unknown to this verifier version; entry checked, payload not",
	"class.UNKNOWN_MANIFEST_FIELD": "manifest field unknown to this verifier version; accepted and reported, all known checks still run",
	"class.FORMAT_ERROR":           "package unreadable / violates schema",
}

var tableDE = i18nTable{
	"report.title":                 "LEDGER — Prüfbericht (ledger-verify)",
	"report.package":               "Prüfpaket",
	"report.chain":                 "Kette",
	"report.spec":                  "Spezifikationsversion",
	"report.created":               "Paket erstellt",
	"report.entries":               "Einträge",
	"report.checkpoints":           "Checkpoints",
	"report.receipts":              "Quittungen",
	"report.receipts_established":  "Herstellerschlüssel durch den Vertrauensanker des Prüfers belegt",
	"report.vendor_list":           "Herstellerschlüsselliste",
	"report.vendor_list_version":   "Version",
	"report.vendor_list_issued":    "ausgestellt",
	"report.vendor_list_root":      "Wurzel",
	"report.time_anchors":          "Zeitzeugen",
	"report.time_anchors_verified": "unabhängig belegt",
	"report.segments":              "Segmente",
	"report.now":                   "Prüfzeitpunkt (now)",
	"report.now_source.flag":       "per --now vorgegeben",
	"report.now_source.package":    "aus verify_args.json des Pakets — vom Vorlegenden gewählt, nicht von diesem Verifier",
	"report.now_source.system":     "Systemuhr",
	"report.freshness":             "Freshness-Fenster",
	"report.result":                "Ergebnis",
	"report.exit":                  "Exit-Code",
	"report.findings":              "Befunde",
	"report.no_findings":           "Keine Befunde.",
	"report.seq":                   "seq",
	"report.notes":                 "Hinweise",
	"report.first_ts":              "Erster Eintrag",
	"report.last_ts":               "Letzter Eintrag",
	"note.genesis_license":         "GENESIS (seq 1) stammt aus Spezifikation 1.7 oder älter, und seine license_id ist kein Lizenz-Commitment: Bis 1.7 konnte dort der Lizenzschlüssel selbst stehen, und dann kennt ihn jeder Inhaber dieses Pakets — den Schlüssel vom Hersteller ersetzen lassen (Spezifikation 4.1). Ohne Einfluss auf das Ergebnis; der Wert wird nicht ausgegeben.",
	"report.now_not_determined":    "nicht bestimmt — verify_args.json unbrauchbar (siehe FORMAT_ERROR, Spezifikation 10.8)",
	"note.purpose":                 "Dieser Bericht ist technischer Beleg und unterstützt die Erfüllung von Dokumentationspflichten; er entscheidet selbst keine Rechtsfrage.",

	// Kettenende (Spezifikation 8.6). Die %-Verben setzt RenderText ein.
	"report.chain_end":                      "Kettenende",
	"report.chain_end_sealed":               "ordnungsgemäß versiegelt am %s (Grund %s, seq %d)",
	"report.chain_end_incomplete":           "nicht versiegelt — letzter Eintrag seq %d (%s) am %s",
	"report.chain_end_critical":             "ein kritischer Eintrag ohne seinen Sofort-Checkpoint (Spezifikation 6.2)",
	"report.chain_end_not_judged":           "nicht bewertet (Formatfehler, Spezifikation 8.6)",
	"report.last_countersigned":             "Letzte Gegenzeichnung",
	"report.last_countersigned_value":       "Checkpoint seq %d, tree_size %d, server_ts %s",
	"report.last_countersigned_key":         "Herstellerschlüssel",
	"report.last_countersigned_established": "durch den Vertrauensanker des Prüfers belegt",
	"report.last_countersigned_unverified":  "NICHT durch einen Vertrauensanker des Prüfers belegt",
	"report.last_countersigned_none":        "keine in diesem Paket",
	"note.chain_end_incomplete":             "Kettenende unvollständig: Alle vorhandenen Einträge sind geprüft, aber das Paket belegt nicht, dass nach seinem letzten Eintrag nichts mehr kam — ein Export aus laufendem Betrieb ohne Export-Siegel, ein Absturz und eine Kürzung sehen offline gleich aus (Spezifikation 8.6).",
	"note.chain_end_sealed":                 "Versiegelt belegt nicht, dass dies das jüngste Siegel der Kette ist: Das Siegel zeigt, wie dieses Paket endet, nicht den jüngsten Stand der Kette — eine hinter einem früheren Siegel gekürzte Kette sieht gleich aus, und jedes Export-Siegel ist eine solche Stelle (Spezifikation 8.6, 11.2).",

	// Vollständigkeit (Spezifikation 8.6, ab 1.9) und das gemessene
	// Restfenster (Spezifikation 11.2, ab 1.9). Die %-Verben setzt RenderText ein.
	"report.completeness":                 "Vollständigkeit",
	"report.completeness_established":     "belegt bis tree_size %d durch die übergebene erwartete Wurzel (Spezifikation 8.6)",
	"report.completeness_not_established": "nicht belegt — keine vom Hersteller gegengezeichnete Wurzel übergeben und gefunden (Spezifikation 8.6)",
	"note.completeness_not_established":   "Vollständigkeit: Ohne eine vom Hersteller gegengezeichnete Wurzel ist keine Aussage darüber möglich, ob dieses Paket die ganze Kette bis zu seiner Anforderung enthält — ob versiegelt oder nicht (Spezifikation 8.6, 11.2). Eine volle Aussage braucht die Anker-Historie des Herstellers: für chain_id %s selbst abholen (Heartbeat-Spezifikation 9.7) und erneut prüfen mit jeder Wurzel daraus, die VOR der Anforderung dieses Pakets festgehalten wurde — mindestens der jüngsten gegengezeichneten, nie einer späteren: Eine später festgehaltene Wurzel liegt hinter dem Ende des Pakets und widerspräche auch einem ehrlichen —, als --expect-root <tree_size>:<merkle_root> (gefunden, wenn die Wurzel über genau die ersten tree_size Einträge ihr gleicht) oder --expect-root <merkle_root> (gefunden, wenn die Wurzel über irgendein Präfix ihr gleicht); im Browser: Feld für die erwartete Wurzel. Enthält das Paket sie nicht, fehlen Einträge, die der Hersteller gegengezeichnet hatte: MERKLE_INCONSISTENT.",
	"note.completeness_established":       "Vollständigkeit belegt bis tree_size %d durch die übergebene erwartete Wurzel (Spezifikation 8.6): Das Paket enthält die Kette so weit, wie diese Wurzel reicht. Über Einträge nach tree_size %d sagt sie nichts — dafür jede Wurzel aus der Anker-Historie des Herstellers übergeben, die vor der Anforderung dieses Pakets festgehalten wurde.",
	"report.residual_window":              "Restfenster",
	"report.residual_window_value":        "%d Einträge (seq %d bis %d) nach tree_size %d, Dauer %s",
	"report.residual_window_none":         "alle %d Einträge (seq 1 bis %d): kein gegengezeichneter Checkpoint in diesem Paket",
	"report.residual_window_beyond":       "über dem Verankerungstakt",
	"note.residual_window_measured":       "Restfenster (Spezifikation 11.2): Die %d Einträge nach dem letzten gegengezeichneten Stand (tree_size %d) — seq %d bis %d, von %s bis %s, %s — sind noch nicht extern verankert; der Schlüsselinhaber könnte sie spurlos umschreiben. Anker-Nachrichten der Kette ohne Gegenzeichnung in diesem Paket: %d.",
	"note.residual_window_none":           "Restfenster (Spezifikation 11.2): Dieses Paket enthält keinen gegengezeichneten Checkpoint, keiner seiner %d Einträge (seq 1 bis %d, der letzte am %s) ist also vom Hersteller extern verankert; der Schlüsselinhaber könnte sie spurlos umschreiben. Anker-Nachrichten der Kette ohne Gegenzeichnung in diesem Paket: %d.",
	"note.residual_window_beyond":         "Das Restfenster überschreitet den Verankerungstakt (ein Anker alle 5 Minuten, Toleranz 450.000 ms). Mögliche Ursachen: Lizenz abgelaufen (der Hersteller zeichnet nicht mehr gegen), Egress abgeschaltet, Hersteller nicht erreichbar oder ein alter Export. Was der Hersteller bis dahin gegengezeichnet hatte, zeigt nur der Abgleich mit einer von ihm gegengezeichneten Wurzel (Spezifikation 8.6, siehe Hinweis zur Vollständigkeit).",

	// Löschsperren, die am Kettenende aktiv sind (Spezifikation 4.24, 9.3).
	"report.legal_holds":               "Legal Hold aktiv",
	"report.legal_hold_value":          "%s: Umfang %s bis %s, gesetzt bei seq %d, Anlass %s",
	"report.legal_hold_scope_replaced": "Umfang ersetzt bei seq %d",

	"exit.0": "gültig ohne Befunde",
	"exit.1": "gültig mit Befunden",
	"exit.2": "ungültig",
	"exit.3": "Formatfehler",
	"exit.4": "unvollständig: Kettenende nicht versiegelt",

	"class.SEQ_BREAK":              "Sequenzlücke oder -sprung",
	"class.HASH_MISMATCH":          "Hash-Kette gebrochen",
	"class.SIG_INVALID":            "Checkpoint-Signatur ungültig",
	"class.MERKLE_INCONSISTENT":    "Merkle-Konsistenz zwischen verankerten Roots verletzt",
	"class.RECEIPT_INVALID":        "Hersteller-Gegensignatur ungültig",
	"class.TIME_ANCHOR_INVALID":    "Zeitzeuge widerspricht dem Checkpoint oder ist gefälscht",
	"class.FORK_DETECTED":          "Quittung passt zu keiner Präfix-Historie",
	"class.CLOCK_ANOMALY":          "Zeitwiderspruch ohne verketteten CLOCK_JUMP",
	"class.CONCEALED_SILENCE":      "Stille im Kettenverlauf ohne deckenden GAP/RESTART",
	"class.HANDOVER_BROKEN":        "SEAL/RESUME-Handover gebrochen",
	"class.MISSING_CHECKPOINT":     "kritischer Eintrag ohne unmittelbar folgenden Checkpoint",
	"class.CONTENT_MISMATCH":       "vorgelegter Klartext widerspricht Commitment",
	"class.REPORT_MISMATCH":        "vorgelegter Bericht nicht in der Kette",
	"class.UNSEALED_END":           "Kette endet ohne Siegel: unvollständig (Abschnitt 8.6)",
	"class.COVERED_GAP":            "ausgewiesene Lücke (GAP)",
	"class.COVERED_SOURCE_GAP":     "ausgewiesene Quell-Lücke",
	"class.RECONCILIATION_DELTA":   "Abgleich-Differenz zur Anbieter-Angabe",
	"class.CONTENT_DELETED":        "Inhalt fristgerecht gelöscht, Kette intakt",
	"class.HOLD_VIOLATION":         "Inhalt trotz aktiver Löschsperre gelöscht (Abschnitt 9.3)",
	"class.CLOCK_JUMP_NOTE":        "ausgewiesener Uhrensprung",
	"class.TRAILING_SILENCE":       "Kette endet vor dem Freshness-Fenster",
	"class.NO_ANCHOR":              "keine externe Verankerung vorhanden",
	"class.TIME_ANCHOR_UNVERIFIED": "Zeitzeuge vorhanden, seine Stelle aber nicht unabhängig belegt",
	"class.RECEIPT_UNVERIFIED":     "Hersteller-Gegensignatur stimmig, ihr Schlüssel aber nicht durch einen Vertrauensanker des Prüfers belegt",
	"class.SPEC_NEWER":             "Paket nutzt eine neuere Minor-Version der Spezifikation als der Verifier",
	"class.UNKNOWN_ENTRY_TYPE":     "Eintragstyp dieser Verifier-Version unbekannt; Eintrag geprüft, Nutzlast nicht",
	"class.UNKNOWN_MANIFEST_FIELD": "Manifest-Feld dieser Verifier-Version unbekannt; angenommen und gemeldet, alle bekannten Prüfungen laufen weiter",
	"class.FORMAT_ERROR":           "Prüfpaket nicht lesbar/schema-widrig",
}
