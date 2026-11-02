package common

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
)

// PickFreeHTTPPort returns a free TCP port on listenIP within [minPort, maxPort],
// trying ports in a random order so the HTTP listener binds an unpredictable
// port. A port is considered free when it can be bound on listenIP. An empty
// listenIP or "0.0.0.0" binds on all interfaces for the probe.
//
// It returns an error when the range is invalid or when no port in the range can
// be bound.
func PickFreeHTTPPort(listenIP string, minPort, maxPort int) (int, error) {
	if minPort < 1 || maxPort > 65535 || minPort > maxPort {
		return 0, fmt.Errorf("invalid HTTP port range %d-%d (expected 1..65535 with min<=max)", minPort, maxPort)
	}

	host := listenIP
	if host == "" {
		host = "0.0.0.0"
	}

	// Try the candidates in a random order rather than scanning linearly.
	span := maxPort - minPort + 1
	for _, off := range rand.Perm(span) {
		port := minPort + off
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue // in use or not bindable; try the next
		}
		ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no free TCP port found in range %d-%d on %s", minPort, maxPort, host)
}

// ResolveHTTPListenPort returns the port the HTTP listener should bind. When a
// range is requested (maxPort > 0) it picks a random free port in [minPort,
// maxPort]; otherwise it returns httpPort, defaulting to 80 when httpPort is 0.
func ResolveHTTPListenPort(listenIP string, httpPort, minPort, maxPort int) (int, error) {
	if maxPort > 0 || minPort > 0 {
		return PickFreeHTTPPort(listenIP, minPort, maxPort)
	}
	if httpPort == 0 {
		return 80, nil
	}
	return httpPort, nil
}
