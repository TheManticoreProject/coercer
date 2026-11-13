package results

import (
	"archive/zip"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

func readZipPart(t *testing.T, path, part string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("output is not a valid zip: %s", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == part {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("opening %s: %s", part, err)
			}
			defer rc.Close()
			data, _ := io.ReadAll(rc)
			return string(data)
		}
	}
	t.Fatalf("part %s missing from workbook", part)
	return ""
}

func TestExportMethodsXLSX(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.xlsx")
	rs := []MethodResult{
		{
			Target:      "dc01",
			Protocol:    "MS-EFSR",
			Function:    "EfsRpcOpenFileRaw",
			Opnum:       0,
			Transport:   "ncacn_np",
			Pipe:        `\efsrpc`,
			ExploitPath: `\\10.0.0.5\x & <y>`,
			Trigger:     methods.TriggerResult{Status: 0x35},
			Outcome:     OutcomePathResolved,
			Auth:        &AuthResult{Domain: "LAB", Username: "DC01$", NTLMVersion: 2, HashcatLine: "hash"},
		},
	}
	if err := ExportMethodsXLSX(path, rs); err != nil {
		t.Fatalf("ExportMethodsXLSX: %s", err)
	}

	// Required OOXML parts must be present and the file a valid zip.
	for _, part := range []string{"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"} {
		readZipPart(t, path, part)
	}

	sheet := readZipPart(t, path, "xl/worksheets/sheet1.xml")
	if !strings.Contains(sheet, "Exploit Path") {
		t.Error("header row missing from sheet")
	}
	if !strings.Contains(sheet, "EfsRpcOpenFileRaw") {
		t.Error("data value missing from sheet")
	}
	// XML-significant characters in the path must be escaped.
	if !strings.Contains(sheet, "&amp;") || !strings.Contains(sheet, "&lt;y&gt;") {
		t.Errorf("special characters not escaped in sheet: %s", sheet)
	}
	if strings.Contains(sheet, "x & <y>") {
		t.Error("raw unescaped special characters present in sheet")
	}
}

func TestColName(t *testing.T) {
	cases := map[int]string{0: "A", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA"}
	for i, want := range cases {
		if got := colName(i); got != want {
			t.Errorf("colName(%d) = %q, want %q", i, got, want)
		}
	}
}
