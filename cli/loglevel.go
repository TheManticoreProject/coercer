package cli

import (
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
)

// ParseLogLevel maps a --minimum-log-level value to a Manticore logger level.
// Accepted values (case-insensitive): "debug", "info", "warn"/"warning",
// "error". ok is false for any other value.
func ParseLogLevel(s string) (level logger.Level, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return logger.LevelDebug, true
	case "info":
		return logger.LevelInfo, true
	case "warn", "warning":
		return logger.LevelWarn, true
	case "error":
		return logger.LevelError, true
	default:
		return logger.LevelInfo, false
	}
}

// ResolveLogLevel picks the effective logger level from the verbosity flags.
// An explicit --minimum-log-level wins; otherwise -v/--verbose or --debug select
// debug output, and the default is info. ok is false only when minLevel is set
// to an unrecognised value.
func ResolveLogLevel(verbose, debug bool, minLevel string) (level logger.Level, ok bool) {
	if strings.TrimSpace(minLevel) != "" {
		return ParseLogLevel(minLevel)
	}
	if verbose || debug {
		return logger.LevelDebug, true
	}
	return logger.LevelInfo, true
}
