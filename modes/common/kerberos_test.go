package common

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func TestNewKerberosClientPassword(t *testing.T) {
	creds, err := credentials.NewCredentials("CORP", "user", "Passw0rd!", "")
	if err != nil {
		t.Fatalf("NewCredentials: %s", err)
	}
	kc, err := NewKerberosClient(creds, "dc.corp.local")
	if err != nil {
		t.Fatalf("NewKerberosClient: %s", err)
	}
	if kc == nil {
		t.Fatal("expected non-nil Kerberos client")
	}
}

func TestNewKerberosClientNoSecret(t *testing.T) {
	t.Setenv("KRB5CCNAME", "") // ensure the ccache-from-env fallback finds nothing
	creds, err := credentials.NewCredentials("CORP", "user", "", "")
	if err != nil {
		t.Fatalf("NewCredentials: %s", err)
	}
	if _, err := NewKerberosClient(creds, "dc.corp.local"); err == nil {
		t.Error("expected an error when no secret and no ccache are available")
	}
}

func TestConfigureKerberosDisabled(t *testing.T) {
	creds, _ := credentials.NewCredentials("CORP", "user", "pw", "")
	connOpts := ConnectOpts{Target: "host.corp.local"}
	if err := ConfigureKerberos(&connOpts, creds, false, "", ""); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if connOpts.Kerberos != nil || connOpts.SPN != "" || connOpts.SMBSPN != "" {
		t.Errorf("disabled Kerberos must not set client/SPN, got kc=%v spn=%q smbspn=%q", connOpts.Kerberos, connOpts.SPN, connOpts.SMBSPN)
	}
}

func TestConfigureKerberosEnabledBuildsSPN(t *testing.T) {
	creds, _ := credentials.NewCredentials("CORP", "user", "pw", "")
	connOpts := ConnectOpts{Target: "host.corp.local"}
	if err := ConfigureKerberos(&connOpts, creds, true, "dc.corp.local", ""); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if connOpts.Kerberos == nil {
		t.Error("enabled Kerberos must set a client")
	}
	if connOpts.SPN != "host/host.corp.local" {
		t.Errorf("SPN = %q, want %q", connOpts.SPN, "host/host.corp.local")
	}
	if connOpts.SMBSPN != "cifs/host.corp.local" {
		t.Errorf("SMBSPN = %q, want %q", connOpts.SMBSPN, "cifs/host.corp.local")
	}
}

func TestConfigureKerberosInvalidAESKey(t *testing.T) {
	creds, _ := credentials.NewCredentials("CORP", "user", "pw", "")
	connOpts := ConnectOpts{Target: "host.corp.local"}
	if err := ConfigureKerberos(&connOpts, creds, true, "dc", "not-valid-hex"); err == nil {
		t.Error("expected an error for an invalid AES key")
	}
}
