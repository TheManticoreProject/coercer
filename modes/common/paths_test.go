package common

import "testing"

func TestEffectivePathIP(t *testing.T) {
	cases := []struct {
		name     string
		override string
		fallback string
		want     string
	}{
		{"no override uses fallback", "", "10.0.0.1", "10.0.0.1"},
		{"override wins", "192.168.1.5", "10.0.0.1", "192.168.1.5"},
		{"empty both", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectivePathIP(tc.override, tc.fallback); got != tc.want {
				t.Errorf("EffectivePathIP(%q, %q) = %q, want %q", tc.override, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestResolvePathIP(t *testing.T) {
	cases := []struct {
		name         string
		override     string
		listenIP     string
		target       string
		want         string
		wantDetected bool
	}{
		{"override wins", "192.168.1.5", "10.0.0.1", "127.0.0.1", "192.168.1.5", false},
		{"override wins over unspecified", "192.168.1.5", "0.0.0.0", "127.0.0.1", "192.168.1.5", false},
		{"specific listener address", "", "10.0.0.1", "127.0.0.1", "10.0.0.1", false},
		{"unspecified listener detects route", "", "0.0.0.0", "127.0.0.1", "127.0.0.1", true},
		{"empty listener detects route", "", "", "127.0.0.1", "127.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, detected, err := ResolvePathIP(tc.override, tc.listenIP, tc.target)
			if err != nil {
				t.Fatalf("ResolvePathIP: %v", err)
			}
			if got != tc.want || detected != tc.wantDetected {
				t.Errorf("ResolvePathIP(%q, %q, %q) = %q, %v; want %q, %v", tc.override, tc.listenIP, tc.target, got, detected, tc.want, tc.wantDetected)
			}
		})
	}
}
