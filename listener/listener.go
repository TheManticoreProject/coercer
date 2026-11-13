package listener

import (
	"github.com/TheManticoreProject/manticore-coercer/results"
)

type Listener interface {
	Start() error
	Stop() error
	Results() <-chan results.AuthResult
}
