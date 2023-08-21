package tls

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	l, err := zap.NewDevelopment()
	logger = l.Sugar().Named("tls").WithOptions(zap.AddStacktrace(zap.DPanicLevel))
	if err != nil {
		logger = zap.NewNop().Sugar()
	}
}
