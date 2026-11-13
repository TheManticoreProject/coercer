package common

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/manticore-coercer/results"
)

func PrintSummary(allResults []results.MethodResult) {
	if len(allResults) == 0 {
		return
	}

	counts := map[results.CoercionOutcome]int{}
	protoSuccess := map[string]int{}
	for _, r := range allResults {
		counts[r.Outcome]++
		if r.Outcome == results.OutcomeSuccess || r.Outcome == results.OutcomePathResolved {
			protoSuccess[r.Protocol]++
		}
	}

	logger.Print("")
	logger.Info("  Summary:")
	logger.Info(fmt.Sprintf("    %-20s %d", "Total attempts:", len(allResults)))
	if c := counts[results.OutcomeSuccess] + counts[results.OutcomePathResolved]; c > 0 {
		logger.Info(fmt.Sprintf("    \x1b[92m%-20s %d\x1b[0m", "Successful:", c))
	}
	if c := counts[results.OutcomeAccessDenied]; c > 0 {
		logger.Info(fmt.Sprintf("    \x1b[93m%-20s %d\x1b[0m", "Access denied:", c))
	}
	if c := counts[results.OutcomeFaulted]; c > 0 {
		logger.Info(fmt.Sprintf("    \x1b[91m%-20s %d\x1b[0m", "Faulted:", c))
	}
	if c := counts[results.OutcomeNotAvailable]; c > 0 {
		logger.Info(fmt.Sprintf("    \x1b[90m%-20s %d\x1b[0m", "Not available:", c))
	}
	if c := counts[results.OutcomeOther]; c > 0 {
		logger.Info(fmt.Sprintf("    %-20s %d", "Other:", c))
	}

	if len(protoSuccess) > 0 {
		logger.Print("")
		logger.Info("  Successful protocols:")
		for proto, count := range protoSuccess {
			logger.Info(fmt.Sprintf("    \x1b[92m%-20s %d method(s)\x1b[0m", proto, count))
		}
	}
}

func PrintSummaryWithAuth(allResults []results.MethodResult) {
	captured := 0
	for _, r := range allResults {
		if r.Auth != nil {
			captured++
		}
	}

	PrintSummary(allResults)

	if captured > 0 {
		logger.Info(fmt.Sprintf("    \x1b[92m%-20s %d\x1b[0m", "Auth captured:", captured))
	}
}

func PrintFuzzSummary(allResults []results.FuzzResult) {
	if len(allResults) == 0 {
		return
	}

	var mrs []results.MethodResult
	authCaptured := 0
	bindErrors := 0
	for _, fr := range allResults {
		mrs = append(mrs, fr.MethodResult)
		if fr.Auth != nil {
			authCaptured++
		}
		if fr.BindError != nil {
			bindErrors++
		}
	}

	PrintSummary(mrs)

	if authCaptured > 0 {
		logger.Info(fmt.Sprintf("    \x1b[92m%-20s %d\x1b[0m", "Auth captured:", authCaptured))
	}
	if bindErrors > 0 {
		logger.Info(fmt.Sprintf("    \x1b[91m%-20s %d\x1b[0m", "Bind errors:", bindErrors))
	}
}
