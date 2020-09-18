package constants

import (
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	"net/http"
)

const (
	PayloadValidationErrorCode string = "ERR_CRYPTO_SERVICE_PAYLOAD_INVALID"
	InternalServerErrorCode    string = "ERR_CRYPTO_SERVICE_INTERNAL_SERVER_ERROR"
	CryptoServiceFailureCode      string = "ERR_CRYPTO_SERVICE_SERVICE_FAILURE"
	UserAlreadyExistsCode      string = "ERR_CRYPTO_SERVICE_USER_ALREADY_EXISTS"
	RetryRegistrationCode      string = "ERR_CRYPTO_SERVICE_RETRY_REGISTRATION"
	ActivationLinkExpiredCode  string = "ERR_CRYPTO_SERVICE_ACTIVATION_LINK_EXPIRED"
)

var (
	CryptoServiceFailureError           = golaerror.Error{ErrorCode: CryptoServiceFailureCode, ErrorMessage: "Failed to communicate with crypto service"}
	PayloadValidationError           = golaerror.Error{ErrorCode: PayloadValidationErrorCode, ErrorMessage: "One or more of the request parameters are missing or invalid"}
	InternalServerError              = golaerror.Error{ErrorCode: InternalServerErrorCode, ErrorMessage: "something went wrong"}
	RegistrationRetryError           = golaerror.Error{ErrorCode: RetryRegistrationCode, ErrorMessage: "Please retry again", AdditionalData: nil}
	UnableToProcessRegistrationError = golaerror.Error{ErrorCode: CryptoServiceFailureCode, ErrorMessage: "Please try again later", AdditionalData: nil}
	ActivationLinkExpiredError       = golaerror.Error{ErrorCode: ActivationLinkExpiredCode, ErrorMessage: "Please try again or retry registration process", AdditionalData: nil}
)

var ErrorCodeHttpStatusCodeMap = map[string]int{
	PayloadValidationErrorCode: http.StatusBadRequest,
	InternalServerErrorCode:    http.StatusInternalServerError,
	CryptoServiceFailureCode:      http.StatusInternalServerError,
	UserAlreadyExistsCode:      http.StatusFound,
	RetryRegistrationCode:      http.StatusInternalServerError,
	ActivationLinkExpiredCode:  http.StatusUnauthorized,
}

func GetGolaHttpCode(golaErrCode string) int {
	if httpCode, ok := ErrorCodeHttpStatusCodeMap[golaErrCode]; ok {
		return httpCode
	}
	return http.StatusInternalServerError
}

func RespondWithGolaError(ctx *gin.Context, err error) {
	if golaErr, ok := err.(golaerror.Error); ok {
		ctx.JSON(GetGolaHttpCode(golaErr.ErrorCode), golaErr)
		return
	}
	ctx.JSON(http.StatusInternalServerError, InternalServerError)
	return
}
