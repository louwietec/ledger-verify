# ML-DSA known-answer tests (NIST ACVP, sigVer, FIPS 204)

`sigver.json` is a reduced subset of the NIST ACVP test vectors for ML-DSA signature
verification. `verifier2_test.py` (class `MLDSA`) checks every case in it against
`testPassed`.

## Source

- Repository: https://github.com/usnistgov/ACVP-Server
- File: `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`
  (git blob `4c8caf12220e44dfa711fefe20e0285aaad844be`,
  SHA-256 `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`)
- Commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (master, 2026-08-12,
  "RELEASE/v1.1.0.43 including hotfix patches")
- Raw URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
- Retrieved: 2026-11-03

## What was changed (2026-11-03)

The file was reduced; no value was altered. Kept are the top-level members `vsId`,
`algorithm`, `mode` and `revision`, every group member except `tests`, and per case the
members `tcId`, `testPassed`, `reason`, `pk`, `message`, `mu`, `context` and `signature`
where present, with their values exactly as in the source (upper-case hex). Dropped are
`sk`, `deferred` and `hashAlg`.

Groups kept: the nine groups that are not pre-hash, that is the pure external groups 1, 3
and 5 (ML-DSA-44, -65, -87, with context string) and the internal groups 7 to 12 (with
`externalMu` true: `mu` is given; false: `message` is M' itself). The pre-hash groups 2, 4
and 6 (HashML-DSA) are left out; verifier2 implements the pure variant only.

Cases kept per group (10 of 15): all three with `testPassed` true; then, of the failing
ones, every case with an empty or 255-octet context or a one-octet message, the case with
the shortest message for each `reason` not yet covered, and further failing cases by
shortest message until ten.

## Licence

The vectors come from NIST. Software developed by NIST employees is not subject to
copyright protection within the United States (public domain there). The notice of the
ACVP-Server repository, kept intact as it asks:

> NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.

Source: National Institute of Standards and Technology (NIST), ACVP-Server.

# Wycheproof vectors ML-DSA-87 verify (C2SP)

`mldsa_87_verify_test.json` is the complete file of the Wycheproof project, unchanged: 241
cases of ML-DSA-87 signature verification (pure ML-DSA, with and without context string).
Format spec 7.4.5a requires both reference verifiers to pass all 241 cases in their unit
tests with the same result per case; `verifier2_test.py` (class `MLDSA`,
`test_7_4_5a_wycheproof_mldsa_87_verify`) checks every case against `result`.

## Source

- Repository: https://github.com/C2SP/wycheproof
- File: `testvectors_v1/mldsa_87_verify_test.json`
  (git blob `a36d36421cf441440624446d2b8419646609b077`,
  SHA-256 `54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14`)
- Commit: `65ca494727a52944c204441c860b039e6786b99b` (main)
- Raw URL: https://raw.githubusercontent.com/C2SP/wycheproof/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1/mldsa_87_verify_test.json
- Retrieved: 2026-11-15

## Licence

Project Wycheproof is licensed under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). The file is redistributed unmodified.
