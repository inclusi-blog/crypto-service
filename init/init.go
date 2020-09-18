package init

import (
	"crypto-service/configuration"
	"github.com/gin-gonic/gin"
)

func CreateRouter(data *configuration.ConfigData) *gin.Engine {
	router := gin.Default()
	Swagger()
	Objects(data)
	RegisterRouter(router, data)
	return router
}
