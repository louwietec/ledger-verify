# Contract Vectors of the Cloud Messages (Specification 1.8 to 1.10)

**Language: English (German version: `README.de.md`, identical structure)**

These files are the reference values for the vendor side of the licence: what a metadata server MUST decide on activation and on anchors, and what an appliance MAY conclude from its responses. The heartbeat specification (`spec/heartbeat.en.md`) is normative; these vectors make "per specification" checkable byte for byte. The vendor side and the appliance test their code against them.

## 1. Files

| File | Section | Content |
|---|---|---|
| `license_proof.json` | §4.1 | reference values for `license_proof` (`cases`) and presented values the server MUST refuse (`refused`), each with its reason |
| `license_statement.json` | §9.4 | signed licence statements with the verdict a recipient MUST reach: effective (with its state) or ineffective (with the reason) |
| `anchor_refusal.json` | §9.5 | 403 responses to exactly one sent anchor with the appliance's verdict: licence lock or ordinary failure |
| `lueckenzeuge.json` | §9.2 | anchor sequences through a licence lapse with the server's decision after each step: HTTP status, error code, kind of response and reference size afterwards |
| `activation_receipt.json` | §4.1, §9.8 | 200 answers to a rebinding after a key replacement with the appliance's verdict: rebinding accepted or failed (statement for the new commitment and a receipt bound to the activation, both fresh) |
| `statement_signatures.json` | §9.3, §9.4, §9.11 | from edition 1.10: responses whose licence statement carries, next to the wrapper pair, a pair in `statement_signatures`, with the verdict of a receiver after edition 1.9 and after edition 1.10: effective through the wrapper, effective through the pair under the statements key, only the pair under the countersigning key (ineffective), statements key revoked before `server_ts` (ineffective), malformed entry next to the wrapper (ignored) |
| `gemeldete_wurzeln.json` | §9.2, §9.7 | from edition 1.10: two appliances with their own licences and the binding of a chain, with the server decision after each step: a chain is bound by its first recorded root or a registered chain succession, never by a heartbeat; a reported root is recorded only when the chain is bound to the sending appliance; the anchor of another appliance is answered with HTTP 403 `chain_owner_mismatch` |

The vendor keys in the files are **test keys**; their seeds are published in them so that implementations can sign their own cases. They are never configured on a real server.

## 2. Generation and independent check

The files are generated deterministically by the vector generator: `cd appliance && go run ./cmd/vektorgen -vertrag ../spec/contract`. `TestVertragEingefroren` (`appliance/cmd/vektorgen`) holds the committed files byte for byte against the generator. The telemetry checks its implementation of `license_proof` against `license_proof.json` (`TestLicenseProofVertrag`).

Independently of that, `.ci/check_vertrag.py` re-derives every expectation from the specification text: in Python, with the second verifier's primitives (JCS, Ed25519, RFC 6962 tree) and the registry's member sets (`cloud_statements`), without trusting the generator. `.ci/check_registry_matrix.py` runs the check; a disagreement is red.

## 3. What may change

A new case is a new entry. An existing case changes only when the released specification refutes it, as with the frozen test vectors (`spec/testvectors/README.en.md` §4).
