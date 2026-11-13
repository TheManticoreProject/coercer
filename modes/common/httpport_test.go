package common

import (
	"net"
	"strconv"
	"testing"
)

func TestResolveHTTPListenPortFixed(t *testing.T) {
	// No range: returns the explicit port.
	p, err := ResolveHTTPListenPort("127.0.0.1", 8080, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if p != 8080 {
		t.Errorf("port = %d, want 8080", p)
	}

	// No range and no explicit port: defaults to 80.
	p, err = ResolveHTTPListenPort("127.0.0.1", 0, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if p != 80 {
		t.Errorf("port = %d, want 80 (default)", p)
	}
}

func TestResolveHTTPListenPortRange(t *testing.T) {
	// A one-port range on loopback must select exactly that port (and it must be
	// bindable, which a high ephemeral port on 127.0.0.1 is in CI).
	const port = 54987
	p, err := ResolveHTTPListenPort("127.0.0.1", 0, port, port)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if p != port {
		t.Errorf("port = %d, want %d", p, port)
	}
}

func TestResolveHTTPListenPortRangeWithinBounds(t *testing.T) {
	const lo, hi = 55000, 55010
	p, err := ResolveHTTPListenPort("127.0.0.1", 0, lo, hi)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if p < lo || p > hi {
		t.Errorf("port %d is outside [%d,%d]", p, lo, hi)
	}
}

func TestPickFreeHTTPPortInvalidRange(t *testing.T) {
	cases := [][2]int{
		{0, 10},    // min < 1
		{100, 50},  // min > max
		{1, 70000}, // max > 65535
	}
	for _, c := range cases {
		if _, err := PickFreeHTTPPort("127.0.0.1", c[0], c[1]); err == nil {
			t.Errorf("PickFreeHTTPPort(%d,%d) expected an error", c[0], c[1])
		}
	}
}

func TestPickFreeHTTPPortSkipsBoundPort(t *testing.T) {
	// Bind the only port in a one-port range; the picker must then fail.
	const port = 55123
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("could not bind probe port %d: %s", port, err)
	}
	defer ln.Close()
	if _, err := PickFreeHTTPPort("127.0.0.1", port, port); err == nil {
		t.Error("expected failure when the only port in range is already bound")
	}
}
