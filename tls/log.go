package tls

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	logger = zap.NewNop().Sugar()
}
