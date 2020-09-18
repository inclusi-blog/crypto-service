package constants

import (
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	"net/http"
)

const (
	PayloadValidationErrorCode string = "ERR_CRYPTO_SERVICE_PAYLOAD_INVALID"
	InternalServerErrorCode    string = "ERR_CRYPTO_SERVICE_INTERNAL_SERVER_ERROR"
	CryptoServiceFailureCode   string = "ERR_CRYPTO_SERVICE_SERVICE_FAILURE"
	DecryptionErrorCode        string = "ERR_CRYPTO_DECRYPTION_ERROR"
	DecodeErrorCode            string = "ERR_DECODE_ERROR"
	KeyNotFoundErrorCode       string = "ERR_CRYPTO_KEY_NOT_FOUND"
)

var (
	CryptoServiceFailureError = golaerror.Error{ErrorCode: CryptoServiceFailureCode, ErrorMessage: "Failed to communicate with crypto service"}
	PayloadValidationError    = golaerror.Error{ErrorCode: PayloadValidationErrorCode, ErrorMessage: "One or more of the request parameters are missing or invalid"}
	InternalServerError       = golaerror.Error{ErrorCode: InternalServerErrorCode, ErrorMessage: "something went wrong"}
	DecryptionError           = golaerror.Error{ErrorCode: DecryptionErrorCode, ErrorMessage: "Unable to decrypt the text", AdditionalData: nil}
	DecodeError               = golaerror.Error{ErrorCode: DecodeErrorCode, ErrorMessage: "Unable to decode text", AdditionalData: nil}
	KeyNotFoundError          = golaerror.Error{ErrorCode: KeyNotFoundErrorCode, ErrorMessage: "Key not found", AdditionalData: nil}
)

var ErrorCodeHttpStatusCodeMap = map[string]int{
	PayloadValidationErrorCode: http.StatusBadRequest,
	InternalServerErrorCode:    http.StatusInternalServerError,
	CryptoServiceFailureCode:   http.StatusInternalServerError,
	DecryptionErrorCode:        http.StatusInternalServerError,
	DecodeErrorCode:            http.StatusBadRequest,
	KeyNotFoundErrorCode:       http.StatusInternalServerError,
}

func GetGolaHttpCode(golaErrCode string) int {
	if httpCode, ok := ErrorCodeHttpStatusCodeMap[golaErrCode]; ok {
		return httpCode
	}
	return http.StatusInternalServerError
}

func RespondWithGolaError(ctx *gin.Context, err error) {
	if golaErr, ok := err.(*golaerror.Error); ok {
		ctx.JSON(GetGolaHttpCode(golaErr.ErrorCode), golaErr)
		return
	}
	ctx.JSON(http.StatusInternalServerError, InternalServerError)
	return
}
