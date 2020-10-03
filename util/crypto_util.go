package util

// mockgen -source=util/crypto_util.go -destination=mocks/mock_crypto_util.go -package=mocks
import (
	"context"
	"crypto-service/constants"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/golaerror"
	"github.com/gola-glitch/gola-utils/logging"
	"github.com/gola-glitch/gola-utils/model"
	goJoseV2 "gopkg.in/square/go-jose.v2"
	joseJwt "gopkg.in/square/go-jose.v2/jwt"
	"os"
	"strings"
)

type CryptoUtil interface {
	DecodeJwtToken(jwtToken string) (model.IdToken, error)
	Decrypt(key *rsa.PrivateKey, encryptedText string, ctx context.Context) (string, *golaerror.Error)
	GetPrivateKey(ctx *gin.Context, key string) (*rsa.PrivateKey, error)
	EncodePayloadToJWTToken(payload string, key *rsa.PrivateKey) (string, error)
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
	logger := logging.GetLogger(ctx).WithField("class", "CryptoUtil").WithField("method", "GetPrivateKey")
	fileData, fileError := getKeyData(key)
	if fileError != nil {
		logger.Errorf("Error in reading private key %v", fileError)
		return nil, fileError
	}

	data, _ := pem.Decode(fileData)
	if data == nil {
		logger.Error("Private key not found.")
		return nil, errors.New("private key not found")
	}
	privateKey, parsingError := x509.ParsePKCS1PrivateKey(data.Bytes)
	if parsingError != nil {
		logger.Errorf("Error in parsing a private key %v", parsingError)
		return nil, parsingError
	}

	return privateKey, nil
}

func (utils cryptoUtil) EncodePayloadToJWTToken(payload string, key *rsa.PrivateKey) (string, error) {
	var token model.IdToken
	err := json.Unmarshal([]byte(payload), &token)
	if err != nil {
		return "", errors.New("invalid JSON")
	}

	//TODO: No test for this condition
	sig, err := goJoseV2.NewSigner(goJoseV2.SigningKey{Algorithm: goJoseV2.RS256, Key: key}, (&goJoseV2.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	//TODO: No test for this condition
	raw, err := joseJwt.Signed(sig).Claims(token).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}

func (utils cryptoUtil) DecodeJwtToken(jwtToken string) (model.IdToken, error) {
	tokenParts := strings.Split(jwtToken, ".")

	if len(tokenParts) != 3 {
		return model.IdToken{}, errors.New("invalid token format")
	}
	payload := tokenParts[1]
	bytes, decodeErr := jwt.DecodeSegment(payload)
	if decodeErr != nil {
		return model.IdToken{}, decodeErr
	}
	var token model.IdToken
	unmarshalError := json.Unmarshal(bytes, &token)
	if unmarshalError != nil {
		return model.IdToken{}, unmarshalError
	}
	return token, nil
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
