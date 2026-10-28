// Command ledger-verify is the free, offline chain verifier of LEDGER.
// It implements ONLY the open specification in spec/ (format.*.md,
// registry.json) and never imports anything from the appliance module.
//
// The whole command line lives in verifier/internal/cli (flags, exit codes,
// version line); this file only hands it the process. See the package
// documentation there for usage and exit codes.
//
//	ledger-verify [flags] <pruefpaket>     (directory or ZIP)
package main

import (
	"os"

	"louwietec.com/ledger-verify/verifier/internal/cli"
)

func main() {
	// A closed pipe on stdout is a write error that cli.Main answers with
	// exit 3 (spec 10.8), as verifier2 does; without this the runtime ends
	// the process with SIGPIPE on a write to descriptor 1.
	ignoriereSIGPIPE()
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
