package init

import (
	"context"
	"crypto-service/configuration"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/logging"
	"github.com/gola-glitch/gola-utils/middleware/request_response_trace"
	middleware "github.com/gola-glitch/gola-utils/middleware/session_trace"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func RegisterRouter(router *gin.Engine, configData *configuration.ConfigData) {
	router.Use(middleware.SessionTracingMiddleware)
	router.Use(request_response_trace.HttpRequestResponseTracingMiddleware([]request_response_trace.IgnoreRequestResponseLogs{
		{
			PartialApiPath:       "api/crypto/healthz",
			IsRequestLogAllowed:  false,
			IsResponseLogAllowed: false,
		},
	}))

	golaLoggerRegistry := logging.NewLoggerEntry()

	router.Use(logging.LoggingMiddleware(golaLoggerRegistry))

	logLevel := configData.LogLevel
	logger := logging.GetLogger(context.TODO())

	if logLevel != "" {
		logLevelInitErr := golaLoggerRegistry.SetLevel(logLevel)
		if logLevelInitErr != nil {
			logger.Warning("gola_logger.SetLevel failed. Default log level being used", logLevelInitErr.Error())
		}
	}

	router.GET("api/crypto/v1/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("api/crypto/healthz", healthController.GetHealth)

}
