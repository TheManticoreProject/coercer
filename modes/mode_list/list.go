package mode_list

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"

	"github.com/TheManticoreProject/manticore-coercer/filter"
	"github.com/TheManticoreProject/manticore-coercer/methods"
)

type Options struct {
	Filter filter.Filter
}

func Run(opts Options) {
	registry := methods.DefaultRegistry()

	methodCount := 0
	accessCount := 0
	protoCount := 0

	for _, proto := range registry.Protocols() {
		protoMethods := registry.ByProtocol(proto)
		if len(protoMethods) == 0 {
			continue
		}

		var matched []methods.Method
		for _, m := range protoMethods {
			if opts.Filter.MatchMethod(m) {
				matched = append(matched, m)
			}
		}
		if len(matched) == 0 {
			continue
		}

		type methodLine struct {
			function  string
			opnum     uint16
			accessStr string
		}
		var lines []methodLine
		visibleMethods := 0

		for _, m := range matched {
			hasAccess := false
			for _, access := range m.Access {
				if !opts.Filter.MatchAccess(access) {
					continue
				}

				transport := access.Transport.String()
				pipe := access.Pipe
				auth := access.DefaultAuth.String()

				if access.ForbidAuth {
					auth = "none (forbidden)"
				}

				var accessLine string
				if pipe != "" {
					accessLine = fmt.Sprintf("[%s] pipe: %s", transport, pipe)
				} else {
					accessLine = fmt.Sprintf("[%s]", transport)
				}

				lines = append(lines, methodLine{
					function:  m.Function,
					opnum:     m.Opnum,
					accessStr: fmt.Sprintf("%s  auth: %s  %s", accessLine, auth, formatSyntaxes(access.Syntaxes)),
				})
				hasAccess = true
				accessCount++
			}
			if hasAccess {
				visibleMethods++
			}
		}

		if visibleMethods == 0 {
			continue
		}

		logger.Info(fmt.Sprintf("  \x1b[96m%s\x1b[0m (%s) — %d method(s)", proto, matched[0].ProtocolLong, visibleMethods))
		for _, l := range lines {
			logger.Info(fmt.Sprintf("    %-50s opnum %-3d  %s", l.function, l.opnum, l.accessStr))
		}
		methodCount += visibleMethods
		protoCount++
		logger.Print("")
	}

	logger.Info(fmt.Sprintf("  Total: %d methods, %d access paths across %d protocols.",
		methodCount, accessCount, protoCount))
}

func formatSyntaxes(syntaxes []syntax.SyntaxID) string {
	if len(syntaxes) == 0 {
		return ""
	}
	parts := make([]string, len(syntaxes))
	for i, s := range syntaxes {
		parts[i] = s.String()
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, ", "))
}
