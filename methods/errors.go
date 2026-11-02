package methods

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/windows/errors/win32"
)

func StatusName(status uint32) string {
	// HRESULT with FACILITY_WIN32 (0x8007xxxx): extract the low 16 bits as a Win32 code.
	if status&0xFFFF0000 == 0x80070000 {
		inner := win32.WIN32_ERROR(status & 0xFFFF)
		if name := inner.Name(); name != "" {
			return "HRESULT(" + name + ")"
		}
		return fmt.Sprintf("HRESULT(0x%08x)", status)
	}

	code := win32.WIN32_ERROR(status)
	if name := code.Name(); name != "" {
		return name
	}
	return fmt.Sprintf("0x%08x", status)
}

func FormatStatus(status uint32) string {
	return fmt.Sprintf("%s (0x%08x)", StatusName(status), status)
}
