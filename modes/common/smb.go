package common

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/TheManticoreProject/Manticore/logger"
	dcerpctransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport"
	smbtransport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"
	smb2transport "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb2"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	smb2client "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// smbFamily is the SMB protocol family negotiated with a target.
type smbFamily int

const (
	smbFamilyUnknown smbFamily = iota
	smbFamily2
	smbFamily1
)

// negotiatedFamilies remembers, per target address, which SMB family the
// target accepted, so that only the first connection to an SMB1-only host
// pays for the SMB2 negotiate it drops.
var negotiatedFamilies sync.Map // "ip:port" -> smbFamily

// smbSession is an authenticated SMB session with IPC$ connected, over either
// the SMB2 or the SMB1 engine.
type smbSession struct {
	smb2 *smb2client.Client
	smb1 *smbclient.Client
}

// dialSMB connects to the target's SMB server, negotiates SMB 2.0.2 through
// 3.1.1 and falls back to SMB1 when the target refuses SMB2, then
// authenticates (Kerberos when opts.Kerberos is set, NTLM otherwise) and
// connects to IPC$. opts.Timeout bounds the connect and every later read.
func dialSMB(opts ConnectOpts, creds *credentials.Credentials) (*smbSession, error) {
	ip := net.ParseIP(opts.Target)
	if ip == nil {
		ips, err := net.LookupIP(opts.Target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", opts.Target, err)
		}
		ip = ips[0]
	}

	key := net.JoinHostPort(ip.String(), fmt.Sprint(opts.SMBPort))
	family := smbFamilyUnknown
	if v, ok := negotiatedFamilies.Load(key); ok {
		family = v.(smbFamily)
	}

	var smb2Err error
	if family != smbFamily1 {
		sess, err := dialSMB2(ip, opts, creds)
		if err == nil || !isNegotiateError(err) {
			// SMB2 was negotiated; an authentication or IPC$ failure would
			// not be fixed by SMB1.
			if family == smbFamilyUnknown {
				logger.Debug(fmt.Sprintf("SMB2 negotiated with %s", key))
			}
			negotiatedFamilies.Store(key, smbFamily2)
			return sess, err
		}
		if family == smbFamily2 {
			return nil, err
		}
		smb2Err = err
	}

	sess, err := dialSMB1(ip, opts, creds)
	if err == nil || !isNegotiateError(err) {
		if family == smbFamilyUnknown {
			logger.Debug(fmt.Sprintf("SMB2 refused by %s, using SMB1: %v", key, smb2Err))
		}
		negotiatedFamilies.Store(key, smbFamily1)
		return sess, err
	}
	if smb2Err != nil {
		return nil, fmt.Errorf("%w (SMB2: %v)", err, smb2Err)
	}
	return nil, err
}

// negotiateError marks a failure to connect or negotiate, as opposed to a
// failure to authenticate or connect to IPC$, which no other SMB family would
// fix.
type negotiateError struct{ err error }

func (e *negotiateError) Error() string { return e.err.Error() }
func (e *negotiateError) Unwrap() error { return e.err }

func isNegotiateError(err error) bool {
	_, ok := err.(*negotiateError)
	return ok
}

func dialSMB2(ip net.IP, opts ConnectOpts, creds *credentials.Credentials) (*smbSession, error) {
	smb := smb2client.NewClientUsingTCPTransport(ip, opts.SMBPort)
	smb.Connection.ServerName = opts.Target
	if opts.Timeout > 0 {
		smb.Transport.SetTimeout(opts.Timeout)
	}
	// Connect the transport and negotiate separately: only a refused SMB2
	// negotiate is worth retrying with SMB1, not an unreachable port.
	smb.Connection.Server.Host = ip
	smb.Connection.Server.Port = opts.SMBPort
	if err := smb.Transport.Connect(ip, opts.SMBPort); err != nil {
		return nil, fmt.Errorf("smb connect: %w", err)
	}
	if err := smb.Negotiate(); err != nil {
		smb.Disconnect()
		return nil, &negotiateError{fmt.Errorf("smb2 negotiate: %w", err)}
	}

	if opts.Kerberos != nil {
		// Mirror the RPC bind: authenticate the SMB session with Kerberos too,
		// so Kerberos-only credentials (ccache/kirbi/keytab/AES key) work over
		// the named-pipe transport. The SMB service SPN is cifs/<target>.
		if err := smb.SessionSetupKerberosWithClient(opts.Kerberos, opts.SMBSPN); err != nil {
			smb.Disconnect()
			return nil, fmt.Errorf("smb2 kerberos session: %w", err)
		}
	} else if err := smb.SessionSetup(creds); err != nil {
		smb.Disconnect()
		return nil, fmt.Errorf("smb2 session: %w", err)
	}

	if err := smb.TreeConnect("IPC$"); err != nil {
		smb.Logoff()
		smb.Disconnect()
		return nil, fmt.Errorf("smb2 tree IPC$: %w", err)
	}
	return &smbSession{smb2: smb}, nil
}

func dialSMB1(ip net.IP, opts ConnectOpts, creds *credentials.Credentials) (*smbSession, error) {
	smb := smbclient.NewClientUsingTCPTransport(ip, opts.SMBPort)
	if opts.Timeout > 0 {
		smb.Transport.SetTimeout(opts.Timeout)
	}
	if err := smb.Connect(ip, opts.SMBPort); err != nil {
		smb.Disconnect()
		return nil, &negotiateError{fmt.Errorf("smb connect: %w", err)}
	}

	if opts.Kerberos != nil {
		if err := smb.SessionSetupKerberosWithClient(opts.Kerberos, opts.SMBSPN); err != nil {
			smb.Disconnect()
			return nil, fmt.Errorf("smb kerberos session: %w", err)
		}
	} else if err := smb.SessionSetup(creds); err != nil {
		smb.Disconnect()
		return nil, fmt.Errorf("smb session: %w", err)
	}

	if err := smb.TreeConnect("IPC$"); err != nil {
		smb.Logoff()
		smb.Disconnect()
		return nil, fmt.Errorf("smb tree IPC$: %w", err)
	}
	return &smbSession{smb1: smb}, nil
}

// pipeTransport returns the named pipe as a DCE/RPC transport over the
// session's IPC$ tree.
func (s *smbSession) pipeTransport(pipeName string) dcerpctransport.Transport {
	if !strings.HasPrefix(pipeName, `\`) {
		pipeName = `\` + pipeName
	}
	if s.smb2 != nil {
		return smb2transport.New(s.smb2, pipeName)
	}
	return smbtransport.New(s.smb1, pipeName)
}

// close tears down the IPC$ tree, the session and the connection.
func (s *smbSession) close() {
	if s.smb2 != nil {
		s.smb2.TreeDisconnect()
		s.smb2.Logoff()
		s.smb2.Disconnect()
		return
	}
	s.smb1.TreeDisconnect()
	s.smb1.Logoff()
	s.smb1.Disconnect()
}
