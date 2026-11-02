package cli

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/logger"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]logger.Level{
		"debug":   logger.LevelDebug,
		"DEBUG":   logger.LevelDebug,
		"info":    logger.LevelInfo,
		"warn":    logger.LevelWarn,
		"warning": logger.LevelWarn,
		" error ": logger.LevelError,
	}
	for in, want := range cases {
		got, ok := ParseLogLevel(in)
		if !ok {
			t.Errorf("ParseLogLevel(%q) ok=false, want true", in)
			continue
		}
		if got != want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"", "trace", "verbose", "quiet"} {
		if _, ok := ParseLogLevel(bad); ok {
			t.Errorf("ParseLogLevel(%q) ok=true, want false", bad)
		}
	}
}

func TestResolveLogLevel(t *testing.T) {
	// Default: info.
	if lvl, ok := ResolveLogLevel(false, false, ""); !ok || lvl != logger.LevelInfo {
		t.Errorf("default = (%v,%v), want (info,true)", lvl, ok)
	}
	// Verbose or debug: debug.
	if lvl, _ := ResolveLogLevel(true, false, ""); lvl != logger.LevelDebug {
		t.Errorf("verbose = %v, want debug", lvl)
	}
	if lvl, _ := ResolveLogLevel(false, true, ""); lvl != logger.LevelDebug {
		t.Errorf("debug = %v, want debug", lvl)
	}
	// Explicit minimum level wins over verbose/debug.
	if lvl, ok := ResolveLogLevel(true, true, "warn"); !ok || lvl != logger.LevelWarn {
		t.Errorf("explicit warn = (%v,%v), want (warn,true)", lvl, ok)
	}
	// Invalid explicit level: ok=false.
	if _, ok := ResolveLogLevel(false, false, "nope"); ok {
		t.Error("invalid minimum level should return ok=false")
	}
}
