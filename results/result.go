package results

import (
	"strings"
	"time"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

type AuthResult struct {
	FromAddr    string
	Time        time.Time
	AuthType    methods.AuthType
	NTLMVersion int
	HashcatLine string
	HashcatMode int
	Domain      string
	Username    string
}

type MethodResult struct {
	Target      string
	Transport   string
	Pipe        string
	Protocol    string
	Function    string
	Opnum       uint16
	ExploitPath string
	Trigger     methods.TriggerResult
	Outcome     CoercionOutcome
	Auth        *AuthResult
}

type FuzzResult struct {
	MethodResult
	AuthSetting methods.RPCAuthSetting
	BindError   error
}

type CoercionOutcome int

const (
	OutcomeSuccess      CoercionOutcome = iota // Status 0: call succeeded, check listener
	OutcomePathResolved                        // ERROR_BAD_NETPATH/ERROR_BAD_NET_NAME: target tried to resolve path
	OutcomeAccessDenied                        // ERROR_ACCESS_DENIED: method exists but refused
	OutcomeNotAvailable                        // nca_s_unk_if or similar: method/interface not available
	OutcomeFaulted                             // DCE/RPC fault: call never reached the method
	OutcomeOther                               // Unknown/unexpected status
)

func (o CoercionOutcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomePathResolved:
		return "path resolved"
	case OutcomeAccessDenied:
		return "access denied"
	case OutcomeNotAvailable:
		return "not available"
	case OutcomeFaulted:
		return "faulted"
	default:
		return "other"
	}
}

func ClassifyOutcome(tr methods.TriggerResult) CoercionOutcome {
	if tr.Faulted {
		if tr.Err != nil && isNotAvailableError(tr.Err) {
			return OutcomeNotAvailable
		}
		return OutcomeFaulted
	}
	switch tr.Status {
	case 0x00000000:
		return OutcomeSuccess
	case 0x00000035, 0x00000043, 0x80070035, 0x80070043:
		return OutcomePathResolved
	case 0x00000005, 0x80070005:
		return OutcomeAccessDenied
	default:
		return OutcomeOther
	}
}

func isNotAvailableError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no accepted interface syntax") ||
		strings.Contains(msg, "nca_s_unk_if") ||
		strings.Contains(msg, "accepted no presentation context") ||
		strings.Contains(msg, "pipe not available") ||
		strings.Contains(msg, "STATUS_OBJECT_NAME_NOT_FOUND")
}
