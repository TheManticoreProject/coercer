package common

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	smb1server "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-coercer/listener"
)

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	defer probe.Close()
	return probe.Addr().(*net.TCPAddr).Port
}

func testCreds(t *testing.T) *credentials.Credentials {
	t.Helper()
	creds, err := credentials.NewCredentials("CORP", "user", "Password1", "")
	if err != nil {
		t.Fatalf("NewCredentials: %v", err)
	}
	return creds
}

// TestDialSMBNegotiatesSMB2 checks that dialSMB speaks SMB2 to a server that
// only answers SMB 2.0.2 and later, and does not fall back to SMB1 when the
// SMB2 logon itself is refused.
func TestDialSMBNegotiatesSMB2(t *testing.T) {
	port := freeLoopbackPort(t)
	lis, err := listener.NewSMBListener("127.0.0.1", port)
	if err != nil {
		t.Fatalf("NewSMBListener: %v", err)
	}
	if err := lis.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lis.Stop()

	opts := ConnectOpts{Target: "127.0.0.1", SMBPort: port, Timeout: 5 * time.Second}
	_, err = dialSMB(opts, testCreds(t))
	if err == nil || !strings.HasPrefix(err.Error(), "smb2 session") {
		t.Fatalf("dialSMB error = %v, want an SMB2 session failure", err)
	}
	if v, _ := negotiatedFamilies.Load(fmt.Sprintf("127.0.0.1:%d", port)); v != smbFamily2 {
		t.Errorf("cached family = %v, want SMB2", v)
	}
}

// TestDialSMBFallsBackToSMB1 checks that dialSMB falls back to SMB1 against a
// server that refuses SMB2, and remembers it for the next connection.
func TestDialSMBFallsBackToSMB1(t *testing.T) {
	port := freeLoopbackPort(t)
	srv, err := smb1server.NewServer(smb1server.Config{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler, err := smb1server.NewCaptureHandler(smb1server.CaptureConfig{OnCredential: func(smb1server.Credential) {}})
	if err != nil {
		t.Fatalf("NewCaptureHandler: %v", err)
	}
	srv.RegisterHandler(handler)
	go srv.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port))
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	opts := ConnectOpts{Target: "127.0.0.1", SMBPort: port, Timeout: 5 * time.Second}
	for i := 0; i < 2; i++ {
		start := time.Now()
		_, err = dialSMB(opts, testCreds(t))
		if err == nil || !strings.HasPrefix(err.Error(), "smb session") {
			t.Fatalf("attempt %d: dialSMB error = %v, want an SMB1 session failure", i, err)
		}
		if v, _ := negotiatedFamilies.Load(fmt.Sprintf("127.0.0.1:%d", port)); v != smbFamily1 {
			t.Errorf("attempt %d: cached family = %v, want SMB1", i, v)
		}
		t.Logf("attempt %d took %s", i, time.Since(start))
	}
}
