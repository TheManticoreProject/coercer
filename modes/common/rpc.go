package common

import (
	"fmt"
	"net"
	"strings"
	"time"

	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	smbtransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"
	tcptransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/tcp"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

type ConnectOpts struct {
	Target  string
	SMBPort int
	DCEPort int
	Timeout time.Duration
}

func Connect(opts ConnectOpts, access methods.Access, creds *credentials.Credentials) (*dcerpcclient.Client, func(), error) {
	switch access.Transport {
	case methods.TransportNamedPipe:
		return connectNamedPipe(opts, access, creds)
	case methods.TransportTCP:
		return connectTCP(opts, access, creds)
	default:
		return nil, nil, fmt.Errorf("unsupported transport: %s", access.Transport)
	}
}

func connectNamedPipe(opts ConnectOpts, access methods.Access, creds *credentials.Credentials) (*dcerpcclient.Client, func(), error) {
	ip := net.ParseIP(opts.Target)
	if ip == nil {
		ips, err := net.LookupIP(opts.Target)
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("resolve %s: %w", opts.Target, err)
		}
		ip = ips[0]
	}

	smb := smbclient.NewClientUsingTCPTransport(ip, opts.SMBPort)
	if opts.Timeout > 0 {
		smb.Transport.SetTimeout(opts.Timeout)
	}
	if err := smb.Connect(ip, opts.SMBPort); err != nil {
		return nil, nil, fmt.Errorf("smb connect: %w", err)
	}

	if err := smb.SessionSetup(creds); err != nil {
		smb.Disconnect()
		return nil, nil, fmt.Errorf("smb session: %w", err)
	}

	if err := smb.TreeConnect("IPC$"); err != nil {
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("smb tree IPC$: %w", err)
	}

	pipeName := access.Pipe
	if !strings.HasPrefix(pipeName, `\`) {
		pipeName = `\` + pipeName
	}
	transport := smbtransport.New(smb, pipeName)
	rpcClient := dcerpcclient.NewClient(transport)

	if !access.ForbidAuth && access.DefaultAuth.AuthType != 0 {
		if err := rpcClient.SetAuth(access.DefaultAuth.AuthType, access.DefaultAuth.AuthLevel, creds); err != nil {
			smb.TreeDisconnect()
			smb.Logoff()
			smb.Disconnect()
			return nil, nil, fmt.Errorf("rpc auth: %w", err)
		}
	}

	cleanup := func() {
		rpcClient.Close()
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
	}
	return rpcClient, cleanup, nil
}

func connectTCP(opts ConnectOpts, access methods.Access, creds *credentials.Credentials) (*dcerpcclient.Client, func(), error) {
	transport := tcptransport.New(opts.Target, opts.DCEPort)
	if opts.Timeout > 0 {
		transport.SetTimeout(opts.Timeout)
	}
	rpcClient := dcerpcclient.NewClient(transport)

	if !access.ForbidAuth && access.DefaultAuth.AuthType != 0 {
		if err := rpcClient.SetAuth(access.DefaultAuth.AuthType, access.DefaultAuth.AuthLevel, creds); err != nil {
			return nil, nil, fmt.Errorf("rpc auth: %w", err)
		}
	}

	cleanup := func() {
		rpcClient.Close()
	}
	return rpcClient, cleanup, nil
}

func IsUnknownInterface(err error) bool {
	if fault, ok := err.(*pdu.Fault); ok {
		return fault.Status == pdu.NCASUnkIf
	}
	msg := err.Error()
	return strings.Contains(msg, "nca_s_unk_if") || strings.Contains(msg, "accepted no presentation context")
}

func TryTrigger(connOpts ConnectOpts, m methods.Method, access methods.Access, exploitPath string, creds *credentials.Credentials) methods.TriggerResult {
	for _, syn := range access.Syntaxes {
		rpcClient, cleanup, err := Connect(connOpts, access, creds)
		if err != nil {
			return methods.TriggerResult{Faulted: true, Err: err}
		}

		if err := rpcClient.Bind(syn); err != nil {
			cleanup()
			if IsUnknownInterface(err) {
				continue
			}
			return methods.TriggerResult{Faulted: true, Err: fmt.Errorf("bind %s: %w", syn, err)}
		}

		result := m.Trigger(rpcClient, connOpts.Target, exploitPath)
		cleanup()
		return result
	}

	return methods.TriggerResult{Faulted: true, Err: fmt.Errorf("no accepted interface syntax")}
}

func ConnectWithAuth(opts ConnectOpts, access methods.Access, authOverride methods.RPCAuthSetting, creds *credentials.Credentials) (*dcerpcclient.Client, func(), error) {
	overridden := methods.Access{
		Transport:   access.Transport,
		Pipe:        access.Pipe,
		Syntaxes:    access.Syntaxes,
		ForbidAuth:  access.ForbidAuth,
		DefaultAuth: authOverride,
	}
	return Connect(opts, overridden, creds)
}

func TryTriggerWithAuth(connOpts ConnectOpts, m methods.Method, access methods.Access, authOverride methods.RPCAuthSetting, exploitPath string, creds *credentials.Credentials) (trigger methods.TriggerResult, bindErr error) {
	for _, syn := range access.Syntaxes {
		rpcClient, cleanup, err := ConnectWithAuth(connOpts, access, authOverride, creds)
		if err != nil {
			return methods.TriggerResult{Faulted: true, Err: err}, err
		}

		if err := rpcClient.Bind(syn); err != nil {
			cleanup()
			if IsUnknownInterface(err) {
				continue
			}
			return methods.TriggerResult{Faulted: true, Err: err}, err
		}

		result := m.Trigger(rpcClient, connOpts.Target, exploitPath)
		cleanup()
		return result, nil
	}

	noSyn := fmt.Errorf("no accepted interface syntax")
	return methods.TriggerResult{Faulted: true, Err: noSyn}, noSyn
}

func ResolveListenIP(iface, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if iface != "" {
		return ipFromInterface(iface)
	}
	return "0.0.0.0", nil
}

func ipFromInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %q addrs: %w", name, err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String(), nil
		}
	}
	return "", fmt.Errorf("interface %q has no IPv4 address", name)
}
