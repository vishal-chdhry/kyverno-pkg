package tls

import (
	"github.com/go-logr/logr"
)

var logger logr.Logger

func init() {
	logger = logr.Discard()
}
