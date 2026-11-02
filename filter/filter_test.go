package filter

import (
	"testing"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

func TestMatchPipe(t *testing.T) {
	f := Filter{PipeNames: []string{"spool"}}
	if !f.MatchPipe(`\spoolss`) {
		t.Error(`MatchPipe(\spoolss) should match filter "spool"`)
	}
	if f.MatchPipe(`\efsrpc`) {
		t.Error(`MatchPipe(\efsrpc) should not match filter "spool"`)
	}

	empty := Filter{}
	if !empty.MatchPipe(`\anything`) {
		t.Error("empty pipe filter should match any pipe")
	}
}

func TestMatchTransport(t *testing.T) {
	npAccess := methods.Access{Transport: methods.TransportNamedPipe, Pipe: `\efsrpc`}
	tcpAccess := methods.Access{Transport: methods.TransportTCP}

	msrpc := Filter{TransportNames: []string{"msrpc"}}
	if !msrpc.MatchTransport(npAccess) {
		t.Error("msrpc filter should match named-pipe transport")
	}
	if msrpc.MatchTransport(tcpAccess) {
		t.Error("msrpc filter should not match TCP transport")
	}

	empty := Filter{}
	if !empty.MatchTransport(tcpAccess) {
		t.Error("empty transport filter should match any transport")
	}
}

func TestMatchAccessComposesPipeAndTransport(t *testing.T) {
	access := methods.Access{Transport: methods.TransportNamedPipe, Pipe: `\spoolss`}
	// Pipe matches, transport does not -> overall no match.
	f := Filter{PipeNames: []string{"spool"}, TransportNames: []string{"dcerpc"}}
	if f.MatchAccess(access) {
		t.Error("MatchAccess should fail when transport filter excludes the access")
	}
	// Both match.
	f2 := Filter{PipeNames: []string{"spool"}, TransportNames: []string{"msrpc"}}
	if !f2.MatchAccess(access) {
		t.Error("MatchAccess should pass when both pipe and transport match")
	}
}

func TestMatchExploitPath(t *testing.T) {
	smbPath := methods.ExploitPath{AuthType: methods.AuthSMB, Template: `\\{{listener}}\x\f`}
	httpPath := methods.ExploitPath{AuthType: methods.AuthHTTP, Template: `\\{{listener}}@80/x`}

	// Empty path type imposes no restriction: both paths match.
	empty := Filter{}
	if !empty.MatchExploitPath(smbPath) || !empty.MatchExploitPath(httpPath) {
		t.Error("empty --path-type should match every exploit path")
	}

	// "smb" keeps only SMB paths.
	smbOnly := Filter{PathType: "smb"}
	if !smbOnly.MatchExploitPath(smbPath) {
		t.Error(`--path-type smb should match an SMB path`)
	}
	if smbOnly.MatchExploitPath(httpPath) {
		t.Error(`--path-type smb should not match an HTTP path`)
	}

	// "webdav" and its "http" alias keep only HTTP paths.
	for _, pt := range []string{"webdav", "http", "WebDAV"} {
		f := Filter{PathType: pt}
		if !f.MatchExploitPath(httpPath) {
			t.Errorf(`--path-type %q should match an HTTP path`, pt)
		}
		if f.MatchExploitPath(smbPath) {
			t.Errorf(`--path-type %q should not match an SMB path`, pt)
		}
	}

	// "all"/"both" impose no restriction.
	for _, pt := range []string{"all", "both"} {
		f := Filter{PathType: pt}
		if !f.MatchExploitPath(smbPath) || !f.MatchExploitPath(httpPath) {
			t.Errorf(`--path-type %q should match every exploit path`, pt)
		}
	}
}

func TestValidPathType(t *testing.T) {
	for _, ok := range []string{"", "all", "both", "smb", "webdav", "http", "SMB", " webdav "} {
		if !ValidPathType(ok) {
			t.Errorf("ValidPathType(%q) should be true", ok)
		}
	}
	for _, bad := range []string{"webdv", "ftp", "cifs", "smb2"} {
		if ValidPathType(bad) {
			t.Errorf("ValidPathType(%q) should be false", bad)
		}
	}
}
