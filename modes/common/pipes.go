package common

import (
	"fmt"
	"net"
	"sort"
	"strings"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// KnownNamedPipes is the built-in list of commonly-available SMB named pipes,
// used as a fallback when the remote pipes cannot be enumerated (for example
// over an anonymous session). Names are normalized with a single leading
// backslash to match the method access-pipe convention (e.g. `\efsrpc`).
func KnownNamedPipes() []string {
	return []string{
		`\atsvc`,
		`\efsrpc`,
		`\epmapper`,
		`\eventlog`,
		`\InitShutdown`,
		`\lsass`,
		`\lsarpc`,
		`\LSM_API_service`,
		`\netdfs`,
		`\netlogon`,
		`\ntsvcs`,
		`\scerpc`,
		`\spoolss`,
		`\srvsvc`,
		`\W32TIME_ALT`,
		`\wkssvc`,
	}
}

// normalizePipeName returns the pipe name with exactly one leading backslash and
// without a leading `PIPE\` component, so it matches the method access-pipe
// convention (e.g. `efsrpc`, `\efsrpc`, `PIPE\efsrpc` -> `\efsrpc`).
func normalizePipeName(name string) string {
	name = strings.TrimLeft(name, `\`)
	if len(name) >= 5 && strings.EqualFold(name[:5], `PIPE\`) {
		name = name[5:]
	}
	name = strings.TrimLeft(name, `\`)
	return `\` + name
}

// ListRemotePipes enumerates the SMB named pipes on the target by listing the
// IPC$ share, mirroring impacket's listPath("IPC$", "*"). Returned names are
// normalized (single leading backslash) and sorted. An anonymous or
// insufficiently-privileged session will usually fail here; callers should fall
// back to KnownNamedPipes in that case.
func ListRemotePipes(opts ConnectOpts, creds *credentials.Credentials) ([]string, error) {
	ip := net.ParseIP(opts.Target)
	if ip == nil {
		ips, err := net.LookupIP(opts.Target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", opts.Target, err)
		}
		ip = ips[0]
	}

	smb := smbclient.NewClientUsingTCPTransport(ip, opts.SMBPort)
	if opts.Timeout > 0 {
		smb.Transport.SetTimeout(opts.Timeout)
	}
	if err := smb.Connect(ip, opts.SMBPort); err != nil {
		return nil, fmt.Errorf("smb connect: %w", err)
	}
	defer smb.Disconnect()

	if err := smb.SessionSetup(creds); err != nil {
		return nil, fmt.Errorf("smb session: %w", err)
	}
	defer smb.Logoff()

	if err := smb.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("smb tree IPC$: %w", err)
	}
	defer smb.TreeDisconnect()

	entries, err := smb.ListDirectory(`\`)
	if err != nil {
		return nil, fmt.Errorf("list IPC$: %w", err)
	}

	seen := make(map[string]struct{})
	var pipes []string
	for _, e := range entries {
		if e.IsDirectory || e.LongName == "." || e.LongName == ".." || e.LongName == "" {
			continue
		}
		name := normalizePipeName(e.LongName)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pipes = append(pipes, name)
	}
	sort.Slice(pipes, func(i, j int) bool {
		return strings.ToLower(pipes[i]) < strings.ToLower(pipes[j])
	})
	return pipes, nil
}
