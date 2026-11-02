package cli

import (
	"testing"
	"time"
)

func TestDelayDuration(t *testing.T) {
	cases := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"zero", 0, 0},
		{"negative", -3, 0},
		{"one second", 1, time.Second},
		{"five seconds", 5, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DelayDuration(tc.seconds); got != tc.want {
				t.Errorf("DelayDuration(%d) = %v, want %v", tc.seconds, got, tc.want)
			}
		})
	}
}
