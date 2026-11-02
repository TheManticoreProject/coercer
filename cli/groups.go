package cli

import (
	"fmt"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// DelayDuration converts a --delay value expressed in seconds into a
// time.Duration. Non-positive values yield a zero duration (no delay).
func DelayDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// RegisterCommonGroups attaches the groups that every mode shares.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the groups on.
//	debug (*bool): Whether to print debug information.
//	logFile (*string): Path to additionally write ANSI-stripped output to.
//	disableEscapeCodes (*bool): Whether to disable ANSI escape codes (colors).
//	targetHost (*string): Target host IP or hostname.
//	targetsFile (*string): File with target hosts.
//	smbPort (*int): SMB port.
//	dcePort (*int): DCERPC EPM port.
//	httpPort (*int): HTTP listener / exploit-path port.
//	minHTTPPort (*int): Low bound of a random HTTP listener port range.
//	maxHTTPPort (*int): High bound of a random HTTP listener port range.
//	authDomain (*string): The domain to authenticate to.
//	authUsername (*string): The user to authenticate as.
//	authPassword (*string): The password to authenticate with.
//	authHashes (*string): The LM:NT hashes to authenticate with.
//	authNoPass (*bool): Whether to skip the password prompt.
//	filterMethod (*[]string): Filter by method name.
//	filterProtocol (*[]string): Filter by protocol name.
//	filterPipe (*[]string): Filter by pipe name.
//	filterTransport (*[]string): Filter by transport.
//	pathType (*string): Restrict generated UNC paths to "smb" or "webdav".
//	delay (*int): Delay between attempts in seconds.
//	pathIP (*string): IP to substitute into generated exploit paths (overrides the listener IP).
func RegisterCommonGroups(subparser *parser.ArgumentsParser, debug *bool, logFile *string, disableEscapeCodes *bool, targetHost *string, targetsFile *string, smbPort *int, dcePort *int, httpPort *int, minHTTPPort *int, maxHTTPPort *int, dcePorts *[]int, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool, authKerberos *bool, authDCIP *string, authAESKey *string, filterMethod *[]string, filterProtocol *[]string, filterPipe *[]string, filterTransport *[]string, pathType *string, delay *int, pathIP *string) {
	RegisterConfigurationGroup(subparser, debug, logFile, disableEscapeCodes)
	RegisterTargetGroup(subparser, targetHost, targetsFile)
	RegisterAuthenticationGroup(subparser, authDomain, authUsername, authPassword, authHashes, authNoPass, authKerberos, authDCIP, authAESKey)
	RegisterConnectionGroup(subparser, smbPort, dcePort, httpPort, minHTTPPort, maxHTTPPort, dcePorts)
	RegisterFilterGroup(subparser, filterMethod, filterProtocol, filterPipe, filterTransport, pathType)
	RegisterTimingGroup(subparser, delay)
	RegisterPathGroup(subparser, pathIP)
}

// RegisterPathGroup registers the "Paths" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	pathIP (*string): IP to substitute into generated exploit paths (overrides the listener IP).
func RegisterPathGroup(subparser *parser.ArgumentsParser, pathIP *string) {
	group, err := subparser.NewArgumentGroup("Paths")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(pathIP, "", "--path-ip", "", false, "IP to place in generated exploit paths (overrides the listener IP).")
}

// RegisterConfigurationGroup registers the "Configuration" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	debug (*bool): Whether to print debug information.
//	logFile (*string): Path to additionally write ANSI-stripped output to.
//	disableEscapeCodes (*bool): Whether to disable ANSI escape codes (colors).
func RegisterConfigurationGroup(subparser *parser.ArgumentsParser, debug *bool, logFile *string, disableEscapeCodes *bool) {
	group, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
	group.NewStringArgument(logFile, "", "--log-file", "", false, "Also write output (ANSI-stripped) to this log file.")
	group.NewBoolArgument(disableEscapeCodes, "", "--disable-escape-codes", false, "Disable ANSI escape codes (colors) in output.")
}

// RegisterTargetGroup registers the "Target" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	targetHost (*string): Target host IP or hostname.
//	targetsFile (*string): File with target hosts, one per line.
func RegisterTargetGroup(subparser *parser.ArgumentsParser, targetHost *string, targetsFile *string) {
	group, err := subparser.NewRequiredMutuallyExclusiveArgumentGroup("Target")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(targetHost, "-t", "--target-ip", "", false, "Target host IP or hostname.")
	group.NewStringArgument(targetsFile, "-tf", "--targets-file", "", false, "File with target hosts, one per line.")
}

// RegisterAuthenticationGroup registers the "Authentication" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	authDomain (*string): The domain to authenticate to.
//	authUsername (*string): The user to authenticate as.
//	authPassword (*string): The password to authenticate with.
//	authHashes (*string): The LM:NT hashes to authenticate with.
//	authNoPass (*bool): Whether to skip the password prompt.
func RegisterAuthenticationGroup(subparser *parser.ArgumentsParser, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool, authKerberos *bool, authDCIP *string, authAESKey *string) {
	group, err := subparser.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to.")
	group.NewStringArgument(authUsername, "-u", "--username", "", false, "User to authenticate as.")
	group.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
	group.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	group.NewBoolArgument(authNoPass, "", "--no-pass", false, "Do not ask for a password, bind without one.")
	group.NewBoolArgument(authKerberos, "-k", "--kerberos", false, "Use Kerberos authentication for RPC binds (target must be an FQDN).")
	group.NewStringArgument(authDCIP, "", "--dc-ip", "", false, "KDC / domain controller address for Kerberos (default: resolve from domain).")
	group.NewStringArgument(authAESKey, "", "--aes-key", "", false, "AES128/256 key for Kerberos (pass-the-key).")
}

// RegisterConnectionGroup registers the "Connection" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	smbPort (*int): SMB port.
//	dcePort (*int): DCERPC EPM port.
//	httpPort (*int): HTTP listener / exploit-path port.
//	minHTTPPort (*int): Low bound of a random HTTP listener port range.
//	maxHTTPPort (*int): High bound of a random HTTP listener port range.
func RegisterConnectionGroup(subparser *parser.ArgumentsParser, smbPort *int, dcePort *int, httpPort *int, minHTTPPort *int, maxHTTPPort *int, dcePorts *[]int) {
	group, err := subparser.NewArgumentGroup("Connection")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewTcpPortArgument(smbPort, "", "--smb-port", 445, false, "SMB port.")
	group.NewTcpPortArgument(dcePort, "", "--dce-port", 135, false, "DCERPC endpoint mapper port.")
	group.NewTcpPortArgument(httpPort, "", "--http-port", 80, false, "HTTP listener and exploit-path port.")
	group.NewTcpPortArgument(minHTTPPort, "", "--min-http-port", 0, false, "Low bound of a random HTTP listener port range (with --max-http-port).")
	group.NewTcpPortArgument(maxHTTPPort, "", "--max-http-port", 0, false, "High bound of a random HTTP listener port range (with --min-http-port).")
	group.NewListOfIntsArgument(dcePorts, "", "--dce-ports", []int{}, false, "Explicit DCERPC TCP ports to try (skips endpoint-mapper discovery).")
}

// RegisterFilterGroup registers the "Filter" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	filterMethod (*[]string): Filter by method name (substring, case-insensitive).
//	filterProtocol (*[]string): Filter by protocol name (substring, case-insensitive).
//	filterPipe (*[]string): Filter by pipe name (substring, case-insensitive).
//	filterTransport (*[]string): Filter by transport name.
//	pathType (*string): Restrict generated UNC paths to "smb" or "webdav".
func RegisterFilterGroup(subparser *parser.ArgumentsParser, filterMethod *[]string, filterProtocol *[]string, filterPipe *[]string, filterTransport *[]string, pathType *string) {
	group, err := subparser.NewArgumentGroup("Filter")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewListOfStringsArgument(filterMethod, "", "--filter-method", []string{}, false, "Filter by method name.")
	group.NewListOfStringsArgument(filterProtocol, "", "--filter-protocol", []string{}, false, "Filter by protocol name.")
	group.NewListOfStringsArgument(filterPipe, "", "--filter-pipe", []string{}, false, "Filter by pipe name.")
	group.NewListOfStringsArgument(filterTransport, "", "--filter-transport", []string{}, false, "Filter by transport (msrpc, dcerpc).")
	group.NewStringArgument(pathType, "", "--path-type", "", false, "Restrict generated UNC paths to smb or webdav (default: both). In scan/fuzz this narrows the listener's --auth-type.")
}

// RegisterListenerGroup registers the "Listener" argument group for scan/fuzz modes.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	listenerInterface (*string): Network interface to listen on.
//	listenerIP (*string): Explicit IP address for the listener.
//	authType (*string): Auth type to listen for (smb or http).
func RegisterListenerGroup(subparser *parser.ArgumentsParser, listenerInterface *string, listenerIP *string, authType *string) {
	group, err := subparser.NewArgumentGroup("Listener")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(listenerInterface, "-i", "--listener-interface", "", false, "Network interface to listen on.")
	group.NewStringArgument(listenerIP, "-I", "--listener-ip-address", "", false, "Explicit IP address for the listener.")
	group.NewStringArgument(authType, "", "--auth-type", "smb", false, "Auth type to capture: smb or http.")
}

// RegisterExportGroup registers the "Export" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	exportJSON (*string): JSON export file path.
//	exportXLSX (*string): XLSX export file path.
//	exportSQLite (*string): SQLite export file path.
func RegisterExportGroup(subparser *parser.ArgumentsParser, exportJSON *string, exportXLSX *string, exportSQLite *string) {
	group, err := subparser.NewArgumentGroup("Export")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(exportJSON, "", "--export-json", "", false, "Export results to JSON file.")
	group.NewStringArgument(exportXLSX, "", "--export-xlsx", "", false, "Export results to XLSX file.")
	group.NewStringArgument(exportSQLite, "", "--export-sqlite", "", false, "Export results to SQLite database.")
}

// RegisterTimingGroup registers the "Timing" argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	delay (*int): Delay between attempts in seconds.
func RegisterTimingGroup(subparser *parser.ArgumentsParser, delay *int) {
	group, err := subparser.NewArgumentGroup("Timing")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewIntArgument(delay, "", "--delay", 0, false, "Delay between attempts in seconds.")
}
