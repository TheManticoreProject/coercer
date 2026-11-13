package results

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

func TestExportMethodsSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sqlite")
	rs := []MethodResult{
		{
			Target: "dc01", Protocol: "MS-EFSR", Function: "EfsRpcOpenFileRaw",
			Opnum: 0, Transport: "ncacn_np", Pipe: `\efsrpc`,
			ExploitPath: `\\10.0.0.5\x`, Trigger: methods.TriggerResult{Status: 0x35},
			Outcome: OutcomePathResolved,
			Auth:    &AuthResult{Domain: "LAB", Username: "DC01$", NTLMVersion: 2, HashcatLine: "h"},
		},
		{
			Target: "dc01", Protocol: "MS-RPRN", Function: "RpcRemoteFindFirstPrinterChangeNotification",
			Opnum: 62, Transport: "ncacn_np", Pipe: `\spoolss`,
			ExploitPath: `\\10.0.0.5\y`, Trigger: methods.TriggerResult{Status: 0},
			Outcome: OutcomeSuccess,
		},
	}
	if err := ExportMethodsSQLite(path, rs); err != nil {
		t.Fatalf("ExportMethodsSQLite: %s", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %s", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM results").Scan(&count); err != nil {
		t.Fatalf("count: %s", err)
	}
	if count != 2 {
		t.Errorf("row count = %d, want 2", count)
	}

	var function, authUser string
	var status, ntlm int
	row := db.QueryRow("SELECT function, status, auth_username, ntlm_version FROM results WHERE protocol = 'MS-EFSR'")
	if err := row.Scan(&function, &status, &authUser, &ntlm); err != nil {
		t.Fatalf("scan: %s", err)
	}
	if function != "EfsRpcOpenFileRaw" || status != 0x35 || authUser != "DC01$" || ntlm != 2 {
		t.Errorf("unexpected row: function=%q status=%#x authUser=%q ntlm=%d", function, status, authUser, ntlm)
	}
}

func TestExportFuzzSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fuzz.sqlite")
	rs := []FuzzResult{
		{
			MethodResult: MethodResult{
				Target: "dc01", Protocol: "MS-EFSR", Function: "EfsRpcOpenFileRaw",
				Opnum: 0, Transport: "ncacn_np", Pipe: `\efsrpc`,
				ExploitPath: `\\10.0.0.5\x`, Trigger: methods.TriggerResult{Status: 0},
				Outcome: OutcomeSuccess,
			},
			AuthSetting: methods.RPCAuthNone,
		},
	}
	if err := ExportFuzzSQLite(path, rs); err != nil {
		t.Fatalf("ExportFuzzSQLite: %s", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %s", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM results").Scan(&count); err != nil {
		t.Fatalf("count: %s", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1", count)
	}
}
