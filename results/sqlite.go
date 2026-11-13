package results

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// authFields extracts the captured-auth columns, returning zero values when no
// authentication was captured for the result.
func authFields(a *AuthResult) (domain, username string, ntlmVersion int, hashcatLine string) {
	if a == nil {
		return "", "", 0, ""
	}
	return a.Domain, a.Username, a.NTLMVersion, a.HashcatLine
}

// ExportMethodsSQLite writes scan/coerce results to a SQLite database, creating
// a `results` table and inserting one row per result. It uses the pure-Go,
// cgo-free modernc.org/sqlite driver.
func ExportMethodsSQLite(path string, rs []MethodResult) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS results (
		target        TEXT,
		protocol      TEXT,
		function      TEXT,
		opnum         INTEGER,
		transport     TEXT,
		pipe          TEXT,
		exploit_path  TEXT,
		outcome       TEXT,
		status        INTEGER,
		auth_domain   TEXT,
		auth_username TEXT,
		ntlm_version  INTEGER,
		hashcat_line  TEXT
	)`); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO results
		(target, protocol, function, opnum, transport, pipe, exploit_path, outcome, status, auth_domain, auth_username, ntlm_version, hashcat_line)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, mr := range rs {
		domain, username, ntlm, hashcat := authFields(mr.Auth)
		if _, err := stmt.Exec(
			mr.Target, mr.Protocol, mr.Function, int64(mr.Opnum),
			mr.Transport, mr.Pipe, mr.ExploitPath, mr.Outcome.String(),
			int64(mr.Trigger.Status), domain, username, int64(ntlm), hashcat,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ExportFuzzSQLite writes fuzz results to a SQLite database, creating a
// `results` table (with the extra auth-setting and bind-error columns) and
// inserting one row per result.
func ExportFuzzSQLite(path string, rs []FuzzResult) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS results (
		target        TEXT,
		protocol      TEXT,
		function      TEXT,
		opnum         INTEGER,
		transport     TEXT,
		pipe          TEXT,
		exploit_path  TEXT,
		auth_setting  TEXT,
		outcome       TEXT,
		status        INTEGER,
		bind_error    TEXT,
		auth_domain   TEXT,
		auth_username TEXT,
		ntlm_version  INTEGER,
		hashcat_line  TEXT
	)`); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO results
		(target, protocol, function, opnum, transport, pipe, exploit_path, auth_setting, outcome, status, bind_error, auth_domain, auth_username, ntlm_version, hashcat_line)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, fr := range rs {
		domain, username, ntlm, hashcat := authFields(fr.Auth)
		bindErr := ""
		if fr.BindError != nil {
			bindErr = fr.BindError.Error()
		}
		if _, err := stmt.Exec(
			fr.Target, fr.Protocol, fr.Function, int64(fr.Opnum),
			fr.Transport, fr.Pipe, fr.ExploitPath, fr.AuthSetting.String(),
			fr.Outcome.String(), int64(fr.Trigger.Status), bindErr,
			domain, username, int64(ntlm), hashcat,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
