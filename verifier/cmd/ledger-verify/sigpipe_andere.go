//go:build !unix

package main

// ignoriereSIGPIPE: without Unix signals a write to a closed pipe already
// returns an error, which cli.Main answers with exit 3.
func ignoriereSIGPIPE() {}
