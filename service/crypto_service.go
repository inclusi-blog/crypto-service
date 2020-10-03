package service

// mockgen -source=service/crypto_service.go -destination=mocks/mock_crypto_service.go -package=mocks
import (
	"crypto-service/configuration"
	"crypto-service/constants"
	"crypto-service/models/request"
	model "crypto-service/models/response"
	"crypto-service/util"
	"crypto/rsa"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	loggingUtils "github.com/gola-glitch/gola-utils/logging"
	"gopkg.in/square/go-jose.v2"
	"time"
)

type CryptoService interface {
	DecryptJWE(ctx *gin.Context, request string) (string, error)
	Decrypt(ctx *gin.Context, request string) (model.DecryptResponse, *golaerror.Error)
	EncryptPayloadToJWE(ctx *gin.Context, request request.JWERequest) (model.JWEResponse, *golaerror.Error)
}

type cryptoService struct {
	cryptoUtil util.CryptoUtil
	configData configuration.PublickeyMappingConfiguration
}

func NewCryptoService(cryptoUtil util.CryptoUtil, mappingConfiguration configuration.PublickeyMappingConfiguration) CryptoService {
	return cryptoService{
		cryptoUtil: cryptoUtil,
		configData: mappingConfiguration,
	}
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

func (cryptoService cryptoService) DecryptJWE(ctx *gin.Context, request string) (string, error) {
	logger := loggingUtils.GetLogger(ctx)

	object, err := jose.ParseEncrypted(request)
	if err != nil {
		logger.Error("CryptoService.DecryptJWE: Error in parsing encrypted JWE request")
		return "", err
	}

	privateKey, keyNotFoundError := cryptoService.cryptoUtil.GetPrivateKey(ctx, constants.PRIVATE_KEY)
	if keyNotFoundError != nil {
		logger.Error("CryptoService.DecryptJWE: Error in finding Private Key")
		return "", keyNotFoundError
	}

	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		logger.Error("CryptoService.DecryptJWE: Error in decrypting encrypted JWE request ", err)
		return "", err
	}

	jwtString, err := cryptoService.cryptoUtil.EncodePayloadToJWTToken(string(decrypted), privateKey)
	if err != nil {
		logger.Error("CryptoService.DecryptJWE: Error in encoding JWT ", err)
		return "", err
	}
	logger.Info("CryptoService.EncryptJWT: Successfully decrypted jwe token.")
	return jwtString, nil
}

func (cryptoService cryptoService) EncryptPayloadToJWE(ctx *gin.Context, request request.JWERequest) (model.JWEResponse, *golaerror.Error) {
	logger := loggingUtils.GetLogger(ctx)

	pubkeyData, err := cryptoService.configData.GetKeyData(request.PublicKeyId)
	if err != nil {
		return model.JWEResponse{}, &constants.PayloadValidationError
	}

	publicKey, err := cryptoService.cryptoUtil.GetPublicKey(ctx, pubkeyData.EnvName, constants.PublicKeyType(pubkeyData.EncodingType))
	if err != nil {
		logger.Error("CryptoService.EncryptPayloadToJWE: Error in Finding Public key ", err)
		return model.JWEResponse{}, &constants.InternalServerError
	}
	plaintext, _ := json.Marshal(request.Payload)

	jweToken, tokenGenerationError := cryptoService.makeJWEFromString(ctx, publicKey, plaintext)
	if tokenGenerationError != nil {
		logger.Error("CryptoService.EncryptPayloadToJWE: Error in converting plaintext to jwe ", tokenGenerationError)
		return model.JWEResponse{}, &constants.InternalServerError
	}
	return model.JWEResponse{JWEToken: jweToken}, nil
}

func (cryptoService cryptoService) makeJWEFromString(ctx *gin.Context, publicKey *rsa.PublicKey, plaintext []byte) (string, error) {
	logger := loggingUtils.GetLogger(ctx)
	encrypter, err := cryptoService.cryptoUtil.GetEncrypter(ctx, publicKey)
	if err != nil {
		logger.Error("CryptoService.makeJWEFromString: Error in getting encrypter ", err)
		return "", err
	}

	encryptedJWEObject, err := encrypter.Encrypt(plaintext)
	if err != nil {
		logger.Error("CryptoService.makeJWEFromString: Error in encrypting JWT object ", err)
		return "", err
	}

	jweToken, serializeError := encryptedJWEObject.CompactSerialize()
	if serializeError != nil {
		logger.Error("CryptoService.makeJWEFromString: Error in Serializing JWT token ", err)
		return "", serializeError
	}

	logger.Info("CryptoService.makeJWEFromString.Successfully encrypted jwt token.")
	return jweToken, nil
}
