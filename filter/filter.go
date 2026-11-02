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
	// PathType restricts which UNC exploit-path type is generated: "smb" or
	// "webdav" (alias "http"). An empty value imposes no restriction (both).
	PathType string
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

// MatchExploitPath reports whether an exploit path passes the path-type filter.
// An empty (or unrecognised) PathType imposes no restriction, so every path
// matches; otherwise only paths whose auth type equals the selected one pass.
// "webdav" and "http" both select the HTTP/WebDAV paths.
func (f *Filter) MatchExploitPath(ep methods.ExploitPath) bool {
	want, restricted := NormalizePathType(f.PathType)
	if !restricted {
		return true
	}
	return ep.AuthType == want
}

// NormalizePathType maps a user-supplied --path-type value to the auth type it
// selects. restricted is false when the value imposes no restriction (empty,
// "all" or "both"); ok is false when the value is not a recognised path type.
func NormalizePathType(s string) (want methods.AuthType, restricted bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "smb":
		return methods.AuthSMB, true
	case "webdav", "http":
		return methods.AuthHTTP, true
	default:
		return methods.AuthSMB, false
	}
}

// ValidPathType reports whether s is an accepted --path-type value: empty,
// "all"/"both" (no restriction), "smb", or "webdav"/"http".
func ValidPathType(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all", "both", "smb", "webdav", "http":
		return true
	default:
		return false
	}
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
