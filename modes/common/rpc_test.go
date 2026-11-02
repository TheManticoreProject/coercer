package common

import (
	"reflect"
	"testing"

	"github.com/TheManticoreProject/manticore-coercer/methods"
)

func TestCandidateTCPPorts(t *testing.T) {
	// Non-TCP transports ignore port discovery and return the single DCE port
	// placeholder (unused by the named-pipe path).
	np := methods.Access{Transport: methods.TransportNamedPipe}
	if got := candidateTCPPorts(ConnectOpts{DCEPort: 135}, np); !reflect.DeepEqual(got, []int{135}) {
		t.Errorf("named-pipe candidateTCPPorts = %v, want [135]", got)
	}

	// TCP with an explicit --dce-ports list uses it verbatim and does NOT hit
	// the endpoint mapper.
	tcp := methods.Access{Transport: methods.TransportTCP}
	opts := ConnectOpts{DCEPort: 135, DCEPorts: []int{49152, 49153}}
	if got := candidateTCPPorts(opts, tcp); !reflect.DeepEqual(got, []int{49152, 49153}) {
		t.Errorf("explicit --dce-ports candidateTCPPorts = %v, want [49152 49153]", got)
	}
}

func TestEPMResolvePortsNoSyntaxes(t *testing.T) {
	// With no interface syntaxes there is nothing to map; must return nil
	// without attempting any network connection.
	if got := epmResolvePorts(ConnectOpts{Target: "203.0.113.1", DCEPort: 135}, methods.Access{Transport: methods.TransportTCP}); got != nil {
		t.Errorf("epmResolvePorts with no syntaxes = %v, want nil", got)
	}
}
