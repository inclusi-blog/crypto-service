package service

// mockgen -source=service/crypto_service.go -destination=mocks/mock_crypto_service.go -package=mocks
import (
	"crypto-service/constants"
	model "crypto-service/models/response"
	"crypto-service/util"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	loggingUtils "github.com/gola-glitch/gola-utils/logging"
	"time"
)

type CryptoService interface {
	Decrypt(ctx *gin.Context, request string) (model.DecryptResponse, *golaerror.Error)
}

type cryptoService struct {
	cryptoUtil util.CryptoUtil
}

func NewCryptoService(cryptoUtil util.CryptoUtil) CryptoService {
	return cryptoService{cryptoUtil: cryptoUtil}
}

func (cryptoService cryptoService) Decrypt(ctx *gin.Context, request string) (model.DecryptResponse, *golaerror.Error) {
	startTime := time.Now()
	logger := loggingUtils.GetLogger(ctx).WithField("class", "CryptoService").WithField("method", "Decrypt")
	logger.Debug("Start time of crypto function: ", startTime)

	privateKey, keyNotFoundError := cryptoService.cryptoUtil.GetPrivateKey(ctx, constants.PASSWORD_PRIVATE_KEY)
	if keyNotFoundError != nil {
		logger.Errorf("Error in finding Private Key %v", keyNotFoundError)
		return model.DecryptResponse{}, &constants.KeyNotFoundError
	}

	decryptedText, err := cryptoService.cryptoUtil.Decrypt(privateKey, request, ctx)
	if err != nil {
		logger.Errorf("Error in decrypting Text %v", err)
		return model.DecryptResponse{}, err
	}

	endTime := time.Now()
	logger.Debug("End time of crypto function: ", endTime)
	logger.Debug("Time taken by crypto function: ", endTime.Sub(startTime))

	logger.Info("Decryption successfully.")
	return model.DecryptResponse{DecryptedText: decryptedText}, nil
}
