//go:build windows

package main

import "testing"

// PowerShell's -EncodedCommand wants base64 of UTF-16 little-endian. Getting
// the encoding wrong produces a command that runs but is not the one asked
// for, which is worse than one that fails.
func TestEncodeForPowerShell(t *testing.T) {
	// "hi" -> 'h',0,'i',0 -> aABpAA==
	if got := encodeForPowerShell("hi"); got != "aABpAA==" {
		t.Errorf("encodeForPowerShell(\"hi\") = %q, want %q", got, "aABpAA==")
	}
	// Quotes are the whole reason this exists.
	if encodeForPowerShell(`Write-Host "x"`) == "" {
		t.Error("a quoted command encoded to nothing")
	}
}
