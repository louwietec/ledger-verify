//go:build js && wasm

// Command ledger-verify-wasm ist der freie Verifier von LEDGER als
// WebAssembly-Modul fuer die Pruefung im Browser (verifier/web). Die ganze
// Logik steht in internal/wasmapi; dieses Kommando registriert nur die
// JavaScript-Funktion und bleibt am Leben.
// / The LEDGER verifier as a WebAssembly module; all logic is in internal/wasmapi.
package main

import "louwietec.com/ledger-verify/verifier/internal/wasmapi"

func main() {
	wasmapi.Registrieren()
	// Ein beendetes Go-Programm loescht seine exportierten Funktionen.
	// / A finished Go program removes its exported functions.
	select {}
}
