package init

import (
	"crypto-service/configuration"
	"crypto-service/controller"
	"crypto-service/service"
	"crypto-service/util"
)

var (
	healthController = controller.HealthController{}
	cryptoController controller.CryptoController
)

func Objects(configData *configuration.ConfigData) {
	cryptoUtil := util.NewCryptoUtil()
	mappingConfiguration := configuration.NewPublickeyMappingConfiguration(configData.PublicKeyMap)
	cryptoService := service.NewCryptoService(cryptoUtil, mappingConfiguration)
	cryptoController = controller.NewCryptoController(cryptoService, cryptoUtil)
}
