package common

import (
	"fmt"
	"net"
)

// EffectivePathIP returns the IP address to substitute into generated exploit
// paths. When override (the --path-ip value) is non-empty it takes precedence;
// otherwise the fallback (the listener bind address) is used.
func EffectivePathIP(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

// ResolvePathIP returns the IP address to substitute into the exploit paths of
// a listener-backed mode (scan, fuzz). The --path-ip override wins, then a
// specific listener address. A listener bound to every interface (0.0.0.0,
// when neither -i nor -I is given) is not an address the target can reach, so
// the local address the system routes to the target from is used instead, as
// the reference Coercer does. detected reports whether that lookup happened.
func ResolvePathIP(override, listenIP, target string) (ip string, detected bool, err error) {
	if override != "" {
		return override, false, nil
	}
	if parsed := net.ParseIP(listenIP); parsed != nil && !parsed.IsUnspecified() {
		return listenIP, false, nil
	}
	ip, err = LocalIPForTarget(target)
	if err != nil {
		return "", false, err
	}
	return ip, true, nil
}

// LocalIPForTarget returns the local IP address the system would use to reach
// target. Connecting a UDP socket only selects a route; no packet is sent.
func LocalIPForTarget(target string) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(target, "445"))
	if err != nil {
		return "", fmt.Errorf("no route to %s: %w", target, err)
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.IsUnspecified() {
		return "", fmt.Errorf("no local address routes to %s", target)
	}
	return addr.IP.String(), nil
}
