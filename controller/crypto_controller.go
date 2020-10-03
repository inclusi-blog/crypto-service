package controller

import (
	"crypto-service/constants"
	"crypto-service/models/request"
	"crypto-service/service"
	"crypto-service/util"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gola-glitch/gola-utils/golaerror"
	"github.com/gola-glitch/gola-utils/logging"
	"github.com/gola-glitch/gola-utils/model"
	"net/http"
	"net/url"
)

type CryptoController interface {
	Decrypt(c *gin.Context)
	EncryptIdToken(ctx *gin.Context)
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

// EncryptIdToken godoc
// @Tags IDToken Utility
// @Summary Encrypt id token
// @Description This API will take id token from cookies and returns back the encrypted id token in cookie
// @Accept  json
// @Produce  json
// @Success 200 ""
// @Failure 400 ""
// @Router /api/crypto/id-token/encrypt [get]
func (cryptoController cryptoController) EncryptIdToken(ctx *gin.Context) {
	idToken, idTokenError := cryptoController.getIdTokenFromContext(ctx)
	if idTokenError != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	jweRequest := request.JWERequest{
		PublicKeyId: constants.IDP_PUBLIC_KEY_ID,
		Payload:     idToken,
	}
	encryptedIdToken, inValidJWTError := cryptoController.cryptoService.EncryptPayloadToJWE(ctx, jweRequest)
	if inValidJWTError != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, inValidJWTError)
		return
	}

	http.SetCookie(ctx.Writer, createCookie("enc_id_token", encryptedIdToken.JWEToken))
	ctx.String(http.StatusOK, "")
}

func createCookie(name string, value string) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: url.QueryEscape(value),
	}
}

func (cryptoController cryptoController) getIdTokenFromContext(ctx *gin.Context) (model.IdToken, error) {
	jwtToken, _ := ctx.Cookie("id_token")
	if jwtToken == "" {
		logging.GetLogger(ctx).Error("CryptoController.EncryptIdToken: Cannot find idToken")
		return model.IdToken{}, errors.New("no token found")
	}
	idToken, decodingError := cryptoController.cryptoUtil.DecodeJwtToken(jwtToken)
	if decodingError != nil {
		logging.GetLogger(ctx).Error("CryptoController.EncryptIdToken: Error in decoding jwtToken")
		return model.IdToken{}, errors.New("invalid token format")
	}
	return idToken, nil
}

func (cryptoController cryptoController) handleBadRequestError(bindError error, ctx *gin.Context) {
	logging.GetLogger(ctx).Error("CryptoController: Bad Request Error: ", bindError.Error())
	ctx.AbortWithStatusJSON(http.StatusBadRequest, constants.PayloadValidationError)
}
