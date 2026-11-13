package common

import "testing"

func TestNormalizePipeName(t *testing.T) {
	cases := map[string]string{
		"efsrpc":          `\efsrpc`,
		`\efsrpc`:         `\efsrpc`,
		`\\efsrpc`:        `\efsrpc`,
		`PIPE\efsrpc`:     `\efsrpc`,
		`\PIPE\efsrpc`:    `\efsrpc`,
		`\\PIPE\\spoolss`: `\spoolss`,
		`pipe\srvsvc`:     `\srvsvc`,
	}
	for in, want := range cases {
		if got := normalizePipeName(in); got != want {
			t.Errorf("normalizePipeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownNamedPipes(t *testing.T) {
	pipes := KnownNamedPipes()
	if len(pipes) == 0 {
		t.Fatal("KnownNamedPipes returned empty list")
	}
	seen := make(map[string]bool)
	for _, p := range pipes {
		if len(p) == 0 || p[0] != '\\' {
			t.Errorf("pipe %q is not normalized with a leading backslash", p)
		}
		if seen[p] {
			t.Errorf("duplicate pipe %q in KnownNamedPipes", p)
		}
		seen[p] = true
	}
	for _, must := range []string{`\efsrpc`, `\spoolss`, `\lsarpc`, `\netdfs`, `\eventlog`} {
		if !seen[must] {
			t.Errorf("KnownNamedPipes missing expected pipe %q", must)
		}
	}
}
