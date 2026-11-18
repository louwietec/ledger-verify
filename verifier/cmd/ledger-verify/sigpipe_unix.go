//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

// ignoriereSIGPIPE lets a write to a closed pipe on stdout return an error,
// which cli.Main answers with exit 3, instead of the runtime ending the
// process with SIGPIPE.
func ignoriereSIGPIPE() { signal.Ignore(syscall.SIGPIPE) }
