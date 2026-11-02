package common

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	epmclient "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/epmclient"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	smbtransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"
	tcptransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/tcp"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

type ConnectOpts struct {
	Target   string
	SMBPort  int
	DCEPort  int
	DCEPorts []int
	Timeout  time.Duration

	// Kerberos, when non-nil, makes RPC binds authenticate with Kerberos using
	// this (already identity/secret-configured) client against SPN; otherwise
	// binds use NTLMSSP.
	Kerberos *kerberos.KerberosClient
	SPN      string
	// SMBSPN is the service principal name of the SMB server (cifs/<target>),
	// used to authenticate the named-pipe SMB session with Kerberos when
	// Kerberos is non-nil. It is separate from SPN (host/<target>), which
	// authenticates the DCE/RPC bind.
	SMBSPN string
}

// NewKerberosClient builds a Kerberos client from the given credentials,
// mirroring the secret-priority order used by Manticore's SMB client: ccache,
// kirbi, keytab, AES key, NT hash (RC4/overpass-the-hash), password, and finally
// a ccache from KRB5CCNAME. kdcHost is the KDC/domain-controller address; when
// empty the realm is resolved via DNS-SRV.
func NewKerberosClient(creds *credentials.Credentials, kdcHost string) (*kerberos.KerberosClient, error) {
	kc := kerberos.NewClient(creds.GetUsername(), strings.ToUpper(creds.GetDomain()), kdcHost)
	switch {
	case creds.CanUseCCache():
		if err := kc.LoadTGTFromCCacheFile(creds.GetCCache()); err != nil {
			return nil, fmt.Errorf("load ccache: %w", err)
		}
	case creds.CanUseKirbi():
		if err := kc.LoadTGTFromKirbiFile(creds.GetKirbi()); err != nil {
			return nil, fmt.Errorf("load kirbi: %w", err)
		}
	case creds.CanUseKeytab():
		if err := kc.WithKeytabFile(creds.GetKeytab()); err != nil {
			return nil, fmt.Errorf("load keytab: %w", err)
		}
	case creds.CanUseAESKey():
		if err := kc.WithAESKey(creds.GetAESKey()); err != nil {
			return nil, fmt.Errorf("set AES key: %w", err)
		}
	case creds.CanPassTheHash():
		if err := kc.WithNTHash(creds.GetNTHash()); err != nil {
			return nil, fmt.Errorf("set NT hash: %w", err)
		}
	case creds.GetPassword() != "":
		kc.WithPassword(creds.GetPassword())
	default:
		if err := kc.LoadTGTFromCCacheEnv(); err != nil {
			return nil, fmt.Errorf("no Kerberos secret provided and no usable KRB5CCNAME ccache: %w", err)
		}
	}
	return kc, nil
}

// ConfigureKerberos enables Kerberos RPC authentication on connOpts when
// requested: it applies the AES key to creds, builds the Kerberos client, and
// derives the target SPN (host/<target>). It is a no-op when enabled is false.
func ConfigureKerberos(connOpts *ConnectOpts, creds *credentials.Credentials, enabled bool, kdcHost, aesKey string) error {
	if !enabled {
		return nil
	}
	if aesKey != "" {
		if err := creds.SetAESKey(aesKey); err != nil {
			return fmt.Errorf("invalid AES key: %w", err)
		}
	}
	if net.ParseIP(connOpts.Target) != nil {
		logger.Warn("Kerberos requires an FQDN target; an IP address will fail SPN resolution at the KDC.")
	}
	kc, err := NewKerberosClient(creds, kdcHost)
	if err != nil {
		return err
	}
	connOpts.Kerberos = kc
	connOpts.SPN = "host/" + connOpts.Target
	connOpts.SMBSPN = "cifs/" + connOpts.Target
	return nil
}

// applyRPCAuth configures the RPC client's authentication for an access,
// choosing Kerberos when a Kerberos client is present, otherwise NTLMSSP. It is
// a no-op for accesses that forbid auth or declare no auth type.
func applyRPCAuth(rpcClient *dcerpcclient.Client, opts ConnectOpts, access methods.Access, creds *credentials.Credentials) error {
	if access.ForbidAuth {
		return nil
	}
	if opts.Kerberos != nil {
		authLevel := access.DefaultAuth.AuthLevel
		if authLevel == 0 {
			authLevel = pdu.AuthLevelPktPrivacy
		}
		return rpcClient.SetAuthKerberos(authLevel, opts.Kerberos, opts.SPN)
	}
	if access.DefaultAuth.AuthType != 0 {
		return rpcClient.SetAuth(access.DefaultAuth.AuthType, access.DefaultAuth.AuthLevel, creds)
	}
	return nil
}

const defaultEPMPort = 135

// candidateTCPPorts returns the TCP ports to try for a given access. For
// non-TCP transports it returns a single placeholder (the port is unused by the
// named-pipe path). For TCP it prefers an explicit --dce-ports list; otherwise
// it resolves the interface's dynamic port(s) via the endpoint mapper, falling
// back to the configured DCE port when EPM resolution yields nothing.
func candidateTCPPorts(opts ConnectOpts, access methods.Access) []int {
	if access.Transport != methods.TransportTCP {
		return []int{opts.DCEPort}
	}
	if len(opts.DCEPorts) > 0 {
		return opts.DCEPorts
	}
	if ports := epmResolvePorts(opts, access); len(ports) > 0 {
		return ports
	}
	return []int{opts.DCEPort}
}

// epmResolvePorts queries the endpoint mapper on the target for the dynamic
// ncacn_ip_tcp port(s) of the access's interface syntaxes. It returns nil on
// any failure (callers fall back to the configured DCE port).
func epmResolvePorts(opts ConnectOpts, access methods.Access) []int {
	if len(access.Syntaxes) == 0 {
		return nil
	}
	mapperPort := opts.DCEPort
	if mapperPort == 0 {
		mapperPort = defaultEPMPort
	}

	epm := epmclient.NewOverTCP(opts.Target, mapperPort, opts.Timeout)
	if err := epm.Connect(); err != nil {
		return nil
	}
	defer epm.Close()

	var ports []int
	seen := make(map[int]struct{})
	for _, syn := range access.Syntaxes {
		endpoints, err := epm.Map(syn.UUID, syn.MajorVersion, syn.MinorVersion)
		if err != nil {
			continue
		}
		for _, ep := range endpoints {
			p := int(ep.Port)
			if p == 0 {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	return ports
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

	if opts.Kerberos != nil {
		// Mirror the RPC bind: authenticate the SMB session with Kerberos too,
		// so Kerberos-only credentials (ccache/kirbi/keytab/AES key) work over
		// the named-pipe transport. The SMB service SPN is cifs/<target>.
		if err := smb.SessionSetupKerberosWithClient(opts.Kerberos, opts.SMBSPN); err != nil {
			smb.Disconnect()
			return nil, nil, fmt.Errorf("smb kerberos session: %w", err)
		}
	} else if err := smb.SessionSetup(creds); err != nil {
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

	if err := applyRPCAuth(rpcClient, opts, access, creds); err != nil {
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("rpc auth: %w", err)
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

	if err := applyRPCAuth(rpcClient, opts, access, creds); err != nil {
		return nil, nil, fmt.Errorf("rpc auth: %w", err)
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
	lastErr := fmt.Errorf("no accepted interface syntax")
	for _, port := range candidateTCPPorts(connOpts, access) {
		o := connOpts
		o.DCEPort = port
		for _, syn := range access.Syntaxes {
			rpcClient, cleanup, err := Connect(o, access, creds)
			if err != nil {
				lastErr = err
				break // connection failed on this port; try the next candidate port
			}

			if err := rpcClient.Bind(syn); err != nil {
				cleanup()
				if IsUnknownInterface(err) {
					lastErr = err
					continue // try the next interface syntax on this port
				}
				lastErr = fmt.Errorf("bind %s: %w", syn, err)
				break // try the next candidate port
			}

			result := m.Trigger(rpcClient, o.Target, exploitPath)
			cleanup()
			return result
		}
	}

	return methods.TriggerResult{Faulted: true, Err: lastErr}
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
	lastErr := fmt.Errorf("no accepted interface syntax")
	for _, port := range candidateTCPPorts(connOpts, access) {
		o := connOpts
		o.DCEPort = port
		for _, syn := range access.Syntaxes {
			rpcClient, cleanup, err := ConnectWithAuth(o, access, authOverride, creds)
			if err != nil {
				lastErr = err
				break // connection failed on this port; try the next candidate port
			}

			if err := rpcClient.Bind(syn); err != nil {
				cleanup()
				if IsUnknownInterface(err) {
					lastErr = err
					continue // try the next interface syntax on this port
				}
				lastErr = err
				break // try the next candidate port
			}

			result := m.Trigger(rpcClient, o.Target, exploitPath)
			cleanup()
			return result, nil
		}
	}

	return methods.TriggerResult{Faulted: true, Err: lastErr}, lastErr
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
