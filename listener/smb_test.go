package listener

import (
	"net"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/network/smb"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// startSMBListener starts an SMB listener on a free loopback port.
func startSMBListener(t *testing.T) (*SMBListener, int) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	lis, err := NewSMBListener("127.0.0.1", port)
	if err != nil {
		t.Fatalf("NewSMBListener: %v", err)
	}
	if err := lis.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { lis.Stop() })
	return lis, port
}

// TestSMBListenerCapturesNTLM authenticates to the listener the way a coerced
// Windows host does, and checks that the NTLM response is captured, for an
// SMB2/3 client and for a client that opens with an SMB1 multi-protocol
// negotiate offering SMB2.
func TestSMBListenerCapturesNTLM(t *testing.T) {
	cases := []struct {
		name string
		opts smbclient.Options
		want smb.SMBProtocolVersion
	}{
		{"SMB 3.1.1", smbclient.Options{Preferred: []smb.SMBProtocolVersion{smb.SMB_VERSION_3_1_1}}, smb.SMB_VERSION_3_1_1},
		{"SMB 2.0.2", smbclient.Options{Preferred: []smb.SMBProtocolVersion{smb.SMB_VERSION_2_0_2}}, smb.SMB_VERSION_2_0_2},
		{"SMB1 negotiate upgraded to SMB2", smbclient.Options{
			Preferred: []smb.SMBProtocolVersion{smb.SMB_VERSION_3_1_1, smb.SMB_VERSION_2_0_2, smb.SMB_VERSION_1_0},
			Policy:    smbclient.PolicyHighestInSet,
		}, smb.SMB_VERSION_3_1_1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lis, port := startSMBListener(t)

			c, err := smbclient.Dial("127.0.0.1", port, tc.opts)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Disconnect()
			if got := c.Dialect(); got != tc.want {
				t.Errorf("negotiated %v, want %v", got, tc.want)
			}

			creds, err := credentials.NewCredentials("CORP", "victim", "Password1", "")
			if err != nil {
				t.Fatalf("NewCredentials: %v", err)
			}
			if err := c.Login(creds); err == nil {
				t.Error("Login succeeded, want the capture to refuse it")
			}

			select {
			case ar := <-lis.Results():
				if ar.Username != "victim" || ar.Domain != "CORP" {
					t.Errorf("captured %s\\%s, want CORP\\victim", ar.Domain, ar.Username)
				}
				if ar.HashcatLine == "" {
					t.Error("captured no hashcat line")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no authentication captured")
			}
		})
	}
}
