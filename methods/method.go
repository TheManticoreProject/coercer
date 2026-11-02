package methods

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
)

type AuthType int

const (
	AuthSMB AuthType = iota
	AuthHTTP
)

func (a AuthType) String() string {
	switch a {
	case AuthSMB:
		return "smb"
	case AuthHTTP:
		return "http"
	default:
		return "unknown"
	}
}

type TransportType int

const (
	TransportNamedPipe TransportType = iota
	TransportTCP
)

func (t TransportType) String() string {
	switch t {
	case TransportNamedPipe:
		return "ncacn_np"
	case TransportTCP:
		return "ncacn_ip_tcp"
	default:
		return "unknown"
	}
}

type RPCAuthSetting struct {
	AuthType  uint8
	AuthLevel uint8
}

func (s RPCAuthSetting) String() string {
	if s.AuthType == 0 {
		return "no RPC auth"
	}
	typeName := "unknown"
	switch s.AuthType {
	case pdu.AuthTypeNTLMSSP:
		typeName = "NTLM"
	case pdu.AuthTypeGSSNegotiate:
		typeName = "SPNEGO"
	case pdu.AuthTypeGSSKerberos:
		typeName = "Kerberos"
	}
	levelName := "unknown"
	switch s.AuthLevel {
	case pdu.AuthLevelConnect:
		levelName = "Connect"
	case pdu.AuthLevelCall:
		levelName = "Call"
	case pdu.AuthLevelPkt:
		levelName = "Pkt"
	case pdu.AuthLevelPktIntegrity:
		levelName = "PktIntegrity"
	case pdu.AuthLevelPktPrivacy:
		levelName = "PktPrivacy"
	}
	return fmt.Sprintf("%s+%s", typeName, levelName)
}

var (
	RPCAuthNone          = RPCAuthSetting{0, 0}
	RPCAuthNTLMPrivacy   = RPCAuthSetting{pdu.AuthTypeNTLMSSP, pdu.AuthLevelPktPrivacy}
	RPCAuthNTLMIntegrity = RPCAuthSetting{pdu.AuthTypeNTLMSSP, pdu.AuthLevelPktIntegrity}
	RPCAuthNTLMConnect   = RPCAuthSetting{pdu.AuthTypeNTLMSSP, pdu.AuthLevelConnect}
	RPCAuthNTLMPkt       = RPCAuthSetting{pdu.AuthTypeNTLMSSP, pdu.AuthLevelPkt}
)

// AllRPCAuthSettings returns every auth combination to try during auth fuzzing.
// Manticore's SetAuth currently only supports AuthTypeNTLMSSP.
func AllRPCAuthSettings() []RPCAuthSetting {
	return []RPCAuthSetting{
		RPCAuthNone,
		RPCAuthNTLMConnect,
		RPCAuthNTLMPkt,
		RPCAuthNTLMIntegrity,
		RPCAuthNTLMPrivacy,
	}
}

type Access struct {
	Transport   TransportType
	Pipe        string
	Syntaxes    []syntax.SyntaxID
	DefaultAuth RPCAuthSetting
	ForbidAuth  bool
}

type ExploitPath struct {
	AuthType AuthType
	Template string
}

type TriggerResult struct {
	Status  uint32
	Faulted bool
	Err     error
}

type TriggerFunc func(rpc ndr.Invoker, target string, exploitPath string) TriggerResult

type Method struct {
	Protocol       string
	ProtocolLong   string
	Function       string
	Opnum          uint16
	VulnerableArgs []string
	Access         []Access
	ExploitPaths   []ExploitPath
	Trigger        TriggerFunc
}

// FormatCall renders the Coercer-style method call display:
// Protocol-->Function(Arg=value, ...)
func (m Method) FormatCall(exploitPath string) string {
	pathDisplay := formatPathBytes(exploitPath)
	args := make([]string, len(m.VulnerableArgs))
	for i, arg := range m.VulnerableArgs {
		args[i] = fmt.Sprintf("\x1b[94m%s\x1b[0m=\x1b[93m%s\x1b[0m", arg, pathDisplay)
	}
	return fmt.Sprintf("%s-->\x1b[96m%s\x1b[0m(%s)", m.Protocol, m.Function, strings.Join(args, ", "))
}

func formatPathBytes(path string) string {
	escaped := strings.ReplaceAll(fmt.Sprintf("%q", path), `"`, "")
	return "b'" + strings.ReplaceAll(escaped, `\\`, `\`) + "'"
}
