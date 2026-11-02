package common

// EffectivePathIP returns the IP address to substitute into generated exploit
// paths. When override (the --path-ip value) is non-empty it takes precedence;
// otherwise the fallback (the listener bind address) is used.
func EffectivePathIP(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}
