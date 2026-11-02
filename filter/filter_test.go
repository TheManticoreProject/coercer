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
