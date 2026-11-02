package results

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
)

// writeXLSX writes a minimal single-sheet .xlsx (OOXML SpreadsheetML) workbook
// with no external dependencies. All cells are emitted as inline strings, which
// keeps the writer simple and avoids a shared-string table. headers is the first
// row; rows are the data rows.
func writeXLSX(path, sheetName string, headers []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	parts := map[string]string{
		"[Content_Types].xml":        contentTypesXML,
		"_rels/.rels":                rootRelsXML,
		"xl/workbook.xml":            workbookXML(sheetName),
		"xl/_rels/workbook.xml.rels": workbookRelsXML,
		"xl/worksheets/sheet1.xml":   sheetXML(headers, rows),
	}

	// A fixed, deterministic write order keeps output reproducible.
	order := []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"xl/workbook.xml",
		"xl/_rels/workbook.xml.rels",
		"xl/worksheets/sheet1.xml",
	}
	for _, name := range order {
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			return err
		}
		if _, err := w.Write([]byte(parts[name])); err != nil {
			_ = zw.Close()
			return err
		}
	}
	return zw.Close()
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`

func workbookXML(sheetName string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="` + escapeXML(sanitizeSheetName(sheetName)) + `" sheetId="1" r:id="rId1"/></sheets>
</workbook>`
}

func sheetXML(headers []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)

	writeRow(&b, 1, headers)
	for i, row := range rows {
		writeRow(&b, i+2, row)
	}

	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

func writeRow(b *strings.Builder, rowNum int, cells []string) {
	fmt.Fprintf(b, `<row r="%d">`, rowNum)
	for i, cell := range cells {
		ref := fmt.Sprintf("%s%d", colName(i), rowNum)
		fmt.Fprintf(b, `<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, ref, escapeXML(cell))
	}
	b.WriteString(`</row>`)
}

// colName converts a zero-based column index into a spreadsheet column name
// (0 -> A, 25 -> Z, 26 -> AA, ...).
func colName(i int) string {
	name := ""
	for i >= 0 {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
	}
	return name
}

// sanitizeSheetName enforces the worksheet-name constraints: at most 31
// characters and none of the characters Excel forbids in a sheet name.
func sanitizeSheetName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case ':', '\\', '/', '?', '*', '[', ']':
			return '_'
		}
		return r
	}, name)
	if name == "" {
		name = "Results"
	}
	if len(name) > 31 {
		name = name[:31]
	}
	return name
}

// escapeXML escapes the characters that are significant in XML text and drops
// control characters that are illegal in XML 1.0.
func escapeXML(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// ExportMethodsXLSX writes scan/coerce results to an .xlsx workbook.
func ExportMethodsXLSX(path string, rs []MethodResult) error {
	headers := []string{
		"Target", "Protocol", "Function", "Opnum", "Transport", "Pipe",
		"Exploit Path", "Outcome", "Status", "Auth Domain", "Auth Username",
		"NTLM Version", "Hashcat Line",
	}
	rows := make([][]string, 0, len(rs))
	for _, mr := range rs {
		rows = append(rows, methodResultCells(mr))
	}
	return writeXLSX(path, "Results", headers, rows)
}

// ExportFuzzXLSX writes fuzz results to an .xlsx workbook.
func ExportFuzzXLSX(path string, rs []FuzzResult) error {
	headers := []string{
		"Target", "Protocol", "Function", "Opnum", "Transport", "Pipe",
		"Exploit Path", "Auth Setting", "Outcome", "Status", "Bind Error",
		"Auth Domain", "Auth Username", "NTLM Version", "Hashcat Line",
	}
	rows := make([][]string, 0, len(rs))
	for _, fr := range rs {
		bindErr := ""
		if fr.BindError != nil {
			bindErr = fr.BindError.Error()
		}
		cells := []string{
			fr.Target, fr.Protocol, fr.Function, fmt.Sprintf("%d", fr.Opnum),
			fr.Transport, fr.Pipe, fr.ExploitPath, fr.AuthSetting.String(),
			fr.Outcome.String(), fmt.Sprintf("0x%08x", fr.Trigger.Status), bindErr,
		}
		cells = append(cells, authCells(fr.Auth)...)
		rows = append(rows, cells)
	}
	return writeXLSX(path, "Fuzz", headers, rows)
}

func methodResultCells(mr MethodResult) []string {
	cells := []string{
		mr.Target, mr.Protocol, mr.Function, fmt.Sprintf("%d", mr.Opnum),
		mr.Transport, mr.Pipe, mr.ExploitPath, mr.Outcome.String(),
		fmt.Sprintf("0x%08x", mr.Trigger.Status),
	}
	return append(cells, authCells(mr.Auth)...)
}

func authCells(a *AuthResult) []string {
	if a == nil {
		return []string{"", "", "", ""}
	}
	return []string{a.Domain, a.Username, fmt.Sprintf("%d", a.NTLMVersion), a.HashcatLine}
}
