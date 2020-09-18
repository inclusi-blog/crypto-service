package controller

import (
	"crypto-service/constants"
	"crypto-service/models/request"
	"crypto-service/service"
	"crypto-service/util"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gola-glitch/gola-utils/golaerror"
	"github.com/gola-glitch/gola-utils/logging"
	"net/http"
)

type CryptoController interface {
	Decrypt(c *gin.Context)
}

type cryptoController struct {
	cryptoService service.CryptoService
	cryptoUtil    util.CryptoUtil
}

func NewCryptoController(cryptoService service.CryptoService, cryptoUtil util.CryptoUtil) CryptoController {
	return cryptoController{cryptoService: cryptoService, cryptoUtil: cryptoUtil}
}

// Decrypt given string godoc
// @Tags Decrypt
// @Summary Decrypt string
// @Description This API will takes encrypted string and return the decrypted one
// @Accept  json
// @Produce  json
// @Param DecryptRequest body request.DecryptRequest true "Set decrypt request payload"
// @Success 200 {object} response.DecryptResponse
// @Failure 400 {object} golaerror.Error
// @Failure 500 ""
// @Router /api/crypto/decrypt [post]
func (cryptoController cryptoController) Decrypt(ctx *gin.Context) {
	// for swagger doc import statement needed
	_ = golaerror.Error{}

	var decryptRequest request.DecryptRequest

	if bindError := ctx.ShouldBindBodyWith(&decryptRequest, binding.JSON); bindError != nil {
		cryptoController.handleBadRequestError(bindError, ctx)
		return
	}

	decryptResponse, decryptError := cryptoController.cryptoService.Decrypt(ctx, decryptRequest.EncryptedText)
	if decryptError != nil {
		constants.RespondWithGolaError(ctx, decryptError)
		return
	}

	ctx.JSON(http.StatusOK, decryptResponse)
}

func (cryptoController cryptoController) handleBadRequestError(bindError error, ctx *gin.Context) {
	logging.GetLogger(ctx).Error("CryptoController: Bad Request Error: ", bindError.Error())
	ctx.AbortWithStatusJSON(http.StatusBadRequest, constants.PayloadValidationError)
}
