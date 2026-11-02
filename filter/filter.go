package filter

import (
	"strings"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

type Filter struct {
	MethodNames    []string
	ProtocolNames  []string
	PipeNames      []string
	TransportNames []string
}

func (f *Filter) MatchMethod(m methods.Method) bool {
	if !f.matchStrings(f.MethodNames, m.Function) {
		return false
	}
	if len(f.ProtocolNames) > 0 {
		if !containsSubstring(f.ProtocolNames, m.Protocol) && !containsSubstring(f.ProtocolNames, m.ProtocolLong) {
			return false
		}
	}
	return true
}

func (f *Filter) MatchAccess(a methods.Access) bool {
	return f.MatchPipe(a.Pipe) && f.MatchTransport(a)
}

// MatchTransport reports whether an access passes the transport-name filter,
// ignoring the pipe name.
func (f *Filter) MatchTransport(a methods.Access) bool {
	if len(f.TransportNames) == 0 {
		return true
	}
	transportStr := a.Transport.String()
	alias := transportAlias(a.Transport)
	return containsSubstring(f.TransportNames, transportStr) || containsSubstring(f.TransportNames, alias)
}

// MatchPipe reports whether a bare pipe name passes the pipe-name filter.
func (f *Filter) MatchPipe(pipe string) bool {
	return f.matchStrings(f.PipeNames, pipe)
}

func (f *Filter) matchStrings(filters []string, value string) bool {
	if len(filters) == 0 {
		return true
	}
	return containsSubstring(filters, value)
}

func containsSubstring(filters []string, value string) bool {
	valueLower := strings.ToLower(value)
	for _, f := range filters {
		if strings.Contains(valueLower, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func transportAlias(t methods.TransportType) string {
	switch t {
	case methods.TransportNamedPipe:
		return "msrpc"
	case methods.TransportTCP:
		return "dcerpc"
	default:
		return ""
	}
}
