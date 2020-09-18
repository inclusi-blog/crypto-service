package util

// mockgen -source=util/crypto_util.go -destination=mocks/mock_crypto_util.go -package=mocks
import (
	"context"
	"crypto-service/constants"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	"github.com/gola-glitch/gola-utils/logging"
	"os"
)

type CryptoUtil interface {
	Decrypt(key *rsa.PrivateKey, encryptedText string, ctx context.Context) (string, *golaerror.Error)
	GetPrivateKey(ctx *gin.Context, key string) (*rsa.PrivateKey, error)
}

func NewCryptoUtil() CryptoUtil {
	return cryptoUtil{}
}

type cryptoUtil struct {
}

func (utils cryptoUtil) Decrypt(key *rsa.PrivateKey, encryptedText string, ctx context.Context) (string, *golaerror.Error) {
	log := logging.GetLogger(ctx).WithField("class", "CryptoUtil").WithField("method", "Decrypt")
	cipheredValue, decodeError := base64.StdEncoding.DecodeString(encryptedText)
	if decodeError != nil {
		log.Errorf("Error occurred while decoding string %v", decodeError)
		return "", &constants.DecodeError
	}

	decryptedPassword, decryptionError := rsa.DecryptPKCS1v15(rand.Reader, key, cipheredValue)
	if decryptionError != nil {
		log.Errorf("Error occurred while decrypting value %v", decryptionError)
		return "", &constants.DecryptionError
	}
	return string(decryptedPassword), nil
}

func (utils cryptoUtil) GetPrivateKey(ctx *gin.Context, key string) (*rsa.PrivateKey, error) {
	logger := logging.GetLogger(ctx)
	fileData, fileError := getKeyData(key)
	if fileError != nil {
		logger.Error("Error in reading private key")
		return nil, fileError
	}

	data, _ := pem.Decode(fileData)
	if data == nil {
		logger.Error("Private key not found.")
		return nil, errors.New("private key not found")
	}
	privateKey, parsingError := x509.ParsePKCS1PrivateKey(data.Bytes)
	if parsingError != nil {
		logger.Error("Error in parsing a private key")
		return nil, parsingError
	}

	return privateKey, nil
}

func getKeyData(keyName string) ([]byte, error) {
	var envData []byte
	var envError error
	if os.Getenv(keyName) != "" {
		envData = []byte(os.Getenv(keyName))
		envError = nil
	} else {
		envData = nil
		envError = errors.New("no env variable found")
	}
	return envData, envError
}
