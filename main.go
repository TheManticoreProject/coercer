package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-coercer/cli"
	"github.com/TheManticoreProject/manticore-coercer/filter"
	"github.com/TheManticoreProject/manticore-coercer/modes/common"
	"github.com/TheManticoreProject/manticore-coercer/modes/mode_coerce"
	"github.com/TheManticoreProject/manticore-coercer/modes/mode_fuzz"
	"github.com/TheManticoreProject/manticore-coercer/modes/mode_list"
	"github.com/TheManticoreProject/manticore-coercer/modes/mode_scan"
)

var (
	mode               string
	debug              bool
	logFile            string
	disableEscapeCodes bool

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool

	// Target
	targetHost  string
	targetsFile string

	// Connection
	smbPort     int
	dcePort     int
	connTimeout int

	// Filtering
	filterMethod    []string
	filterProtocol  []string
	filterPipe      []string
	filterTransport []string

	// Scan-specific
	scanListenerInterface string
	scanListenerIP        string
	scanAuthType          string
	scanExportJSON        string
	scanStopOnAuth        bool

	// Coerce-specific
	coerceListenerIP     string
	coerceAlwaysContinue bool
	coerceExportJSON     string

	// Fuzz-specific
	fuzzListenerInterface string
	fuzzListenerIP        string
	fuzzAuthType          string
	fuzzExportJSON        string
	fuzzOnlyKnownPaths    bool
	fuzzAuth              bool

	// List-specific
	listFilterMethod    []string
	listFilterProtocol  []string
	listFilterPipe      []string
	listFilterTransport []string

	// Timing
	delay int

	// Paths
	pathIP string
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "manticore-coercer - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0"}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)
	ap.SetupSubParsing("mode", &mode, true)

	// --- list ---
	subList := ap.AddSubParser("list", "List available coercion methods and access paths.")
	cli.RegisterConfigurationGroup(subList, &debug, &logFile, &disableEscapeCodes)
	registerListOptions(subList)

	// --- scan ---
	subScan := ap.AddSubParser("scan", "Scan for vulnerable coercion methods with known exploit paths.")
	cli.RegisterCommonGroups(subScan, &debug, &logFile, &disableEscapeCodes, &targetHost, &targetsFile, &smbPort, &dcePort, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass, &filterMethod, &filterProtocol, &filterPipe, &filterTransport, &delay, &pathIP)
	cli.RegisterListenerGroup(subScan, &scanListenerInterface, &scanListenerIP, &scanAuthType)
	cli.RegisterExportGroup(subScan, &scanExportJSON)
	registerScanOptions(subScan)
	registerConnectionOptions(subScan)

	// --- coerce ---
	subCoerce := ap.AddSubParser("coerce", "Trigger authentication coercion to an external listener.")
	cli.RegisterCommonGroups(subCoerce, &debug, &logFile, &disableEscapeCodes, &targetHost, &targetsFile, &smbPort, &dcePort, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass, &filterMethod, &filterProtocol, &filterPipe, &filterTransport, &delay, &pathIP)
	cli.RegisterExportGroup(subCoerce, &coerceExportJSON)
	registerCoerceOptions(subCoerce)
	registerConnectionOptions(subCoerce)

	// --- fuzz ---
	subFuzz := ap.AddSubParser("fuzz", "Fuzz exploit paths and auth levels against all methods.")
	cli.RegisterCommonGroups(subFuzz, &debug, &logFile, &disableEscapeCodes, &targetHost, &targetsFile, &smbPort, &dcePort, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass, &filterMethod, &filterProtocol, &filterPipe, &filterTransport, &delay, &pathIP)
	cli.RegisterListenerGroup(subFuzz, &fuzzListenerInterface, &fuzzListenerIP, &fuzzAuthType)
	cli.RegisterExportGroup(subFuzz, &fuzzExportJSON)
	registerFuzzOptions(subFuzz)
	registerConnectionOptions(subFuzz)

	ap.Parse()
}

func registerListOptions(subparser *parser.ArgumentsParser) {
	group, err := subparser.NewArgumentGroup("Filter")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewListOfStringsArgument(&listFilterMethod, "", "--filter-method", []string{}, false, "Filter by method name.")
	group.NewListOfStringsArgument(&listFilterProtocol, "", "--filter-protocol", []string{}, false, "Filter by protocol name.")
	group.NewListOfStringsArgument(&listFilterPipe, "", "--filter-pipe", []string{}, false, "Filter by pipe name.")
	group.NewListOfStringsArgument(&listFilterTransport, "", "--filter-transport", []string{}, false, "Filter by transport.")
}

func registerScanOptions(subparser *parser.ArgumentsParser) {
	group, err := subparser.NewArgumentGroup("Scan options")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(&scanStopOnAuth, "", "--stop-on-auth", false, "Stop after first authentication received per target.")
}

func registerCoerceOptions(subparser *parser.ArgumentsParser) {
	group, err := subparser.NewArgumentGroup("Coerce options")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(&coerceListenerIP, "-l", "--listener-ip", "", true, "IP address of the external listener (e.g. ntlmrelayx).")
	group.NewBoolArgument(&coerceAlwaysContinue, "", "--always-continue", false, "Skip interactive continue/skip/stop prompts.")
}

func registerFuzzOptions(subparser *parser.ArgumentsParser) {
	group, err := subparser.NewArgumentGroup("Fuzz options")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(&fuzzOnlyKnownPaths, "", "--only-known-paths", false, "Restrict fuzzing to known working exploit paths.")
	group.NewBoolArgument(&fuzzAuth, "", "--fuzz-auth", false, "Fuzz RPC authentication type and level combinations.")
}

func registerConnectionOptions(subparser *parser.ArgumentsParser) {
	group, err := subparser.NewArgumentGroup("Timeouts")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewIntArgument(&connTimeout, "", "--timeout", 10, false, "Connection timeout in seconds.")
}

func main() {
	parseArgs()

	if disableEscapeCodes {
		logger.SetNoColors(true)
	}
	if logFile != "" {
		if err := logger.LogToFile(logFile); err != nil {
			logger.Warn(fmt.Sprintf("Cannot open log file: %s", err))
		}
	}

	if !debug {
		logger.SetLevel(logger.LevelInfo)
	}

	if mode == "list" {
		logger.Info("Available coercion methods:")
		logger.Print("")
		mode_list.Run(mode_list.Options{
			Filter: filter.Filter{
				MethodNames:    listFilterMethod,
				ProtocolNames:  listFilterProtocol,
				PipeNames:      listFilterPipe,
				TransportNames: listFilterTransport,
			},
		})
		return
	}

	if err := cli.ResolvePassword(authDomain, authUsername, &authPassword, authNoPass, authHashes); err != nil {
		logger.Warn(err.Error())
		os.Exit(1)
	}
	if authUsername != "" && authPassword == "" && authHashes == "" && !authNoPass {
		logger.Warn("No secret was provided: the bind will be unauthenticated.")
	}

	logger.Info(fmt.Sprintf("Starting manticore-coercer (mode: %s)", mode))

	f := filter.Filter{
		MethodNames:    filterMethod,
		ProtocolNames:  filterProtocol,
		PipeNames:      filterPipe,
		TransportNames: filterTransport,
	}

	timeout := time.Duration(connTimeout) * time.Second

	switch mode {
	case "scan":
		targets := resolveTargets(targetHost, targetsFile)
		if len(targets) == 0 {
			logger.Warn("No targets specified.")
			os.Exit(1)
		}
		for _, target := range targets {
			logger.Info(fmt.Sprintf("  Target: %s", target))
			scanResults := mode_scan.Run(mode_scan.Options{
				Target:            target,
				AuthType:          scanAuthType,
				StopFirst:         scanStopOnAuth,
				ListenerInterface: scanListenerInterface,
				ListenerIP:        scanListenerIP,
				Domain:            authDomain,
				Username:          authUsername,
				Password:          authPassword,
				Hashes:            authHashes,
				SMBPort:           smbPort,
				DCEPort:           dcePort,
				Filter:            f,
				Delay:             cli.DelayDuration(delay),
				ExportJSON:        scanExportJSON,
				Timeout:           timeout,
				PathIP:            pathIP,
			})
			common.PrintSummaryWithAuth(scanResults)
		}
	case "coerce":
		targets := resolveTargets(targetHost, targetsFile)
		if len(targets) == 0 {
			logger.Warn("No targets specified.")
			os.Exit(1)
		}
		for _, target := range targets {
			logger.Info(fmt.Sprintf("  Target: %s", target))
			coerceResults := mode_coerce.Run(mode_coerce.Options{
				Target:         target,
				ListenerIP:     coerceListenerIP,
				AlwaysContinue: coerceAlwaysContinue,
				Domain:         authDomain,
				Username:       authUsername,
				Password:       authPassword,
				Hashes:         authHashes,
				SMBPort:        smbPort,
				DCEPort:        dcePort,
				Filter:         f,
				Delay:          cli.DelayDuration(delay),
				ExportJSON:     coerceExportJSON,
				Timeout:        timeout,
				PathIP:         pathIP,
			})
			common.PrintSummary(coerceResults)
		}
	case "fuzz":
		targets := resolveTargets(targetHost, targetsFile)
		if len(targets) == 0 {
			logger.Warn("No targets specified.")
			os.Exit(1)
		}
		for _, target := range targets {
			logger.Info(fmt.Sprintf("  Target: %s", target))
			fuzzResults := mode_fuzz.Run(mode_fuzz.Options{
				Target:            target,
				AuthType:          fuzzAuthType,
				OnlyKnownPaths:    fuzzOnlyKnownPaths,
				FuzzAuth:          fuzzAuth,
				ListenerInterface: fuzzListenerInterface,
				ListenerIP:        fuzzListenerIP,
				Domain:            authDomain,
				Username:          authUsername,
				Password:          authPassword,
				Hashes:            authHashes,
				SMBPort:           smbPort,
				DCEPort:           dcePort,
				Filter:            f,
				Delay:             cli.DelayDuration(delay),
				ExportJSON:        fuzzExportJSON,
				Timeout:           timeout,
				PathIP:            pathIP,
			})
			common.PrintFuzzSummary(fuzzResults)
		}
	default:
		logger.Warn(fmt.Sprintf("Invalid mode '%s'. Use: list, scan, coerce, or fuzz.", mode))
	}

	logger.Print("Done.")
}

func resolveTargets(host, file string) []string {
	if host != "" {
		return []string{host}
	}
	if file == "" {
		return nil
	}
	f, err := os.Open(file)
	if err != nil {
		logger.Warn(fmt.Sprintf("Cannot open targets file: %s", err))
		return nil
	}
	defer f.Close()
	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets
}
