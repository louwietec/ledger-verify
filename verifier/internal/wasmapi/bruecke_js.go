//go:build js && wasm

package wasmapi

// Die Bruecke zu JavaScript: sie uebersetzt die Argumente von ledgerVerify in
// wert und das Ergebnis von pruefen zurueck, und sonst nichts. Jede Regel
// ueber Namen, Typen, Grammatiken und Grenzen steht in wasmapi.go, damit sie
// auch ohne WebAssembly unter `go test` laeuft.
// / The bridge to JavaScript: converts values, nothing else.

import (
	"syscall/js"
	"time"
)

// wertVon converts a JavaScript value. Arrays are read one level deep: an
// array inside an array is artAnderes, which no option takes. A Uint8Array is
// copied; js.CopyBytesToGo panics for any other type, hence the check.
func wertVon(v js.Value, liste bool) wert {
	switch v.Type() {
	case js.TypeUndefined, js.TypeNull:
		return wert{art: artFehlt}
	case js.TypeString:
		return wert{art: artText, text: v.String()}
	case js.TypeNumber:
		return wert{art: artZahl, zahl: v.Float()}
	case js.TypeBoolean:
		return wert{art: artWahr, wahr: v.Bool()}
	case js.TypeObject:
		if v.InstanceOf(js.Global().Get("Uint8Array")) {
			b := make([]byte, v.Length())
			if len(b) > 0 {
				js.CopyBytesToGo(b, v)
			}
			return wert{art: artBytes, bytes: b}
		}
		if liste && js.Global().Get("Array").Call("isArray", v).Bool() {
			w := wert{art: artListe}
			for i := 0; i < v.Length(); i++ {
				w.liste = append(w.liste, wertVon(v.Index(i), false))
			}
			return w
		}
	}
	return wert{art: artAnderes}
}

func verify(this js.Value, args []js.Value) any {
	if len(args) > 2 {
		return js.ValueOf(fehler("ledgerVerify: hoechstens zwei Argumente, das Pruefpaket und ein Objekt mit Optionen / at most two arguments, the package and an object of options (Spec 10.8)"))
	}
	paket := wert{art: artFehlt}
	if len(args) > 0 {
		paket = wertVon(args[0], false)
	}
	var angaben []angabe
	if len(args) > 1 {
		o := args[1]
		switch {
		case o.IsUndefined() || o.IsNull():
		case o.Type() != js.TypeObject || js.Global().Get("Array").Call("isArray", o).Bool() ||
			o.InstanceOf(js.Global().Get("Uint8Array")):
			return js.ValueOf(fehler("ledgerVerify: zweites Argument muss ein Objekt mit Optionen sein / second argument must be an object of options (Spec 10.8)"))
		default:
			keys := js.Global().Get("Object").Call("keys", o)
			for i := 0; i < keys.Length(); i++ {
				k := keys.Index(i).String()
				angaben = append(angaben, angabe{name: k, wert: wertVon(o.Get(k), true)})
			}
		}
	}
	return js.ValueOf(pruefen(paket, angaben, time.Now))
}

// Registrieren setzt ledgerVerify und ledgerVerifyVersion (und die Aliase unter
// dem frueheren Namen) im globalen JavaScript-Objekt. Der Aufrufer muss danach
// am Leben bleiben (select {}): ein beendetes Go-Programm loescht seine
// exportierten Funktionen. / Registers the globals; the caller must stay alive.
func Registrieren() {
	fn := js.FuncOf(verify)
	js.Global().Set("ledgerVerify", fn)
	v := js.ValueOf(fassung())
	js.Global().Set("ledgerVerifyVersion", v)
	// Aliase unter dem alten Namen: dieselbe Funktion, dasselbe Objekt (kein
	// zweites js.FuncOf, keine Kopie); tests/wasm/seitenprobe.mjs prueft
	// rekorderVerify === ledgerVerify. / Aliases: the same function and object.
	js.Global().Set("rekorderVerify", fn)
	js.Global().Set("rekorderVerifyVersion", v)
}
