package configuration

import (
	"github.com/gola-glitch/gola-utils/model"
)

type ConfigData struct {
	TracingServiceName string                       `json:"tracing_service_name" binding:"required"`
	TracingOCAgentHost string                       `json:"tracing_oc_agent_host" binding:"required"`
	DBConnectionPool   model.DBConnectionPoolConfig `json:"dbConnectionPool" binding:"required"`
	LogLevel           string                       `json:"log_level" binding:"required"`
	Environment        string                       `json:"environment"`
	AllowedOrigins     []string                     `json:"allowed_origins"`
}

func (configData *ConfigData) GetDBConnectionPoolConfig() model.DBConnectionPoolConfig {
	return configData.DBConnectionPool
}
