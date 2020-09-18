package main

import (
	"context"
	. "crypto-service/init"
	"github.com/gola-glitch/gola-utils/logging"
	"github.com/gola-glitch/gola-utils/tracing"
	"net/http"
)

func main() {
	logger := logging.NewLoggerEntry()
	logger.Info("Starting service...")

	logger.Info("Loading configurations")
	configData := LoadConfig()
	router := CreateRouter(configData)
	tracing.Init(configData.TracingServiceName, configData.TracingOCAgentHost)
	err := http.ListenAndServe(":8082", tracing.WithTracing(router, "/api/crypto/healthz"))
	if err != nil {
		logging.GetLogger(context.TODO()).Error("Could not start the server", err)
	}
}
