package controller

import (
	"crypto-service/models/response"
	"github.com/gin-gonic/gin"
	"net/http"
)

type HealthController struct {
}

func (HealthController HealthController) GetHealth(ctx *gin.Context) {
	healthResponse := response.HealthResponse{
		Status: "UP",
	}

	ctx.JSON(http.StatusOK, healthResponse)
}
