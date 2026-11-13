package methods

import (
	"strings"
	"testing"
)

func TestRenderPathListenerAndPorts(t *testing.T) {
	// Non-default HTTP port must surface as an @<port> suffix in HTTP paths.
	httpPath := RenderPath(`\\{{listener}}{{http_listen_port}}/x`, TemplateVars{ListenerIP: "10.0.0.5", HTTPPort: 8080})
	if want := `\\10.0.0.5@8080/x`; httpPath != want {
		t.Errorf("HTTP path = %q, want %q", httpPath, want)
	}

	// HTTPPort 0 falls back to @80.
	httpDefault := RenderPath(`\\{{listener}}{{http_listen_port}}/x`, TemplateVars{ListenerIP: "10.0.0.5"})
	if want := `\\10.0.0.5@80/x`; httpDefault != want {
		t.Errorf("default HTTP path = %q, want %q", httpDefault, want)
	}

	// Default SMB port (445) yields no suffix; a non-default one does.
	smbDefault := RenderPath(`\\{{listener}}{{smb_listen_port}}\s`, TemplateVars{ListenerIP: "10.0.0.5", SMBPort: 445})
	if want := `\\10.0.0.5\s`; smbDefault != want {
		t.Errorf("default SMB path = %q, want %q", smbDefault, want)
	}
	smbCustom := RenderPath(`\\{{listener}}{{smb_listen_port}}\s`, TemplateVars{ListenerIP: "10.0.0.5", SMBPort: 4455})
	if want := `\\10.0.0.5@4455\s`; smbCustom != want {
		t.Errorf("custom SMB path = %q, want %q", smbCustom, want)
	}
}

func TestRenderPathRandomToken(t *testing.T) {
	// {{rnd(n)}} expands to exactly n characters and varies between renders.
	tmpl := `\\h\{{rnd(8)}}`
	a := RenderPath(tmpl, TemplateVars{ListenerIP: "h"})
	rnd := strings.TrimPrefix(a, `\\h\`)
	if len(rnd) != 8 {
		t.Fatalf("rnd token length = %d, want 8 (got %q)", len(rnd), a)
	}
}
