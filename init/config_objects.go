package init

import (
	"crypto-service/configuration"
	"crypto-service/constants"
	"github.com/gola-glitch/gola-utils/configuration_loader"
)

func LoadConfig() *configuration.ConfigData {
	var configData configuration.ConfigData
	err := configuration_loader.NewConfigLoader().Load(constants.FILE_NAME, &configData)

	if err != nil {
		panic(err)
	}
	return &configData
}
