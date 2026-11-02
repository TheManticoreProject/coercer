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
