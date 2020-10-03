package service

import (
	"crypto-service/constants"
	"crypto-service/mocks"
	"crypto-service/models"
	"crypto-service/models/request"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/model"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type CryptoServiceTestSuite struct {
	suite.Suite
	context                *gin.Context
	mockCtrl               *gomock.Controller
	cryptoUtil             *mocks.MockCryptoUtil
	cryptoService          CryptoService
	publicKey              *rsa.PublicKey
	privateKey             *rsa.PrivateKey
	publickeyMappingConfig *mocks.MockPublickeyMappingConfiguration
}

func TestCryptoServiceTestSuite(t *testing.T) {
	suite.Run(t, new(CryptoServiceTestSuite))
}

func (suite *CryptoServiceTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())
	suite.cryptoUtil = mocks.NewMockCryptoUtil(suite.mockCtrl)
	suite.context, _ = gin.CreateTestContext(httptest.NewRecorder())
	suite.context.Request, _ = http.NewRequest("GET", "some-url", nil)
	suite.publickeyMappingConfig = mocks.NewMockPublickeyMappingConfiguration(suite.mockCtrl)
	suite.cryptoService = NewCryptoService(suite.cryptoUtil, suite.publickeyMappingConfig)
}

func (suite *CryptoServiceTestSuite) SetupSuite() {
	suite.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	suite.publicKey = &suite.privateKey.PublicKey
}

func (suite *CryptoServiceTestSuite) TearDownTest() {
	suite.mockCtrl.Finish()
}

func (suite CryptoServiceTestSuite) TestDecryptJWEShouldReturnJWTWhenValidJWEisProvided() {
	idToken, actualJWE := suite.generateJWE()

	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PRIVATE_KEY).Return(suite.privateKey, nil)
	idTokenString, _ := json.Marshal(idToken)
	suite.cryptoUtil.EXPECT().EncodePayloadToJWTToken(string(idTokenString), suite.privateKey).Return("JWT", nil)
	actualJWT, _ := suite.cryptoService.DecryptJWE(suite.context, actualJWE)
	suite.Equal("JWT", actualJWT)
}

func (suite CryptoServiceTestSuite) TestDecryptJWEShouldReturnErrorWhenInValidJWEisProvided() {
	jweToken := "jwe"
	_, err := suite.cryptoService.DecryptJWE(suite.context, jweToken)
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) TestDecryptJWEShouldReturnKeyNotFoundErrorWhenPrivateKeyIsNotProvided() {
	_, actualJWE := suite.generateJWE()

	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PRIVATE_KEY).Return(nil, errors.New("key not found"))
	_, err := suite.cryptoService.DecryptJWE(suite.context, actualJWE)
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) TestDecryptJWEShouldReturnDecrypterErrorWhenPrivateKeyCannotBeDecrypted() {
	_, actualJWE := suite.generateJWE()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PRIVATE_KEY).Return(privateKey, nil)
	_, err := suite.cryptoService.DecryptJWE(suite.context, actualJWE)
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) TestShouldEncodeErrorWhenTamperedPayloadProvided() {
	idToken, actualJWE := suite.generateJWE()

	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PRIVATE_KEY).Return(suite.privateKey, nil)
	idTokenString, _ := json.Marshal(idToken)
	suite.cryptoUtil.EXPECT().EncodePayloadToJWTToken(string(idTokenString),
		suite.privateKey).Return("", errors.New("Encode err"))
	_, err := suite.cryptoService.DecryptJWE(suite.context, actualJWE)
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) generateJWE() (model.IdToken, string) {
	keyData := models.KeyData{
		EncodingType: string(constants.PKCS1PublicKey),
		EnvName:      constants.PUBLIC_KEY,
	}
	idToken := model.IdToken{
		Subject: "",
		UserId:  "dummy-user",
		Email:   "",
	}
	suite.publickeyMappingConfig.EXPECT().GetKeyData(constants.IDP_PUBLIC_KEY_ID).Return(keyData, nil)
	suite.cryptoUtil.EXPECT().GetPublicKey(suite.context, constants.PUBLIC_KEY, constants.PKCS1PublicKey).Return(suite.publicKey, nil)
	encrypter, _ := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: suite.publicKey}, nil)
	suite.cryptoUtil.EXPECT().GetEncrypter(suite.context, suite.publicKey).Return(encrypter, nil)
	jweRequest := request.JWERequest{
		PublicKeyId: constants.IDP_PUBLIC_KEY_ID,
		Payload:     idToken,
	}
	actualJWE, _ := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)
	return idToken, actualJWE.JWEToken
}

func (suite CryptoServiceTestSuite) TestShouldReturnDecryptedTextForGivenEncryptedText() {
	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PASSWORD_PRIVATE_KEY).Return(suite.privateKey, nil)
	suite.cryptoUtil.EXPECT().Decrypt(suite.privateKey, "random_text", suite.context).Return("decrypted_text", nil)
	decryptedResponse, err := suite.cryptoService.Decrypt(suite.context, "random_text")
	suite.Nil(err)
	suite.Equal("decrypted_text", decryptedResponse.DecryptedText)
}

func (suite CryptoServiceTestSuite) TestShouldReturnErrorWhenPrivateKeyForPasswordDecryptionIsNotFound() {
	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PASSWORD_PRIVATE_KEY).Return(nil, errors.New("private key not found"))
	_, err := suite.cryptoService.Decrypt(suite.context, "encrypted_text")
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) TestShouldReturnErrorWhenDecryptionFails() {
	suite.cryptoUtil.EXPECT().GetPrivateKey(suite.context, constants.PASSWORD_PRIVATE_KEY).Return(suite.privateKey, nil)
	suite.cryptoUtil.EXPECT().Decrypt(suite.privateKey, "random_text", suite.context).Return("", &constants.DecryptionError)
	_, err := suite.cryptoService.Decrypt(suite.context, "random_text")
	suite.NotNil(err)
}

func (suite CryptoServiceTestSuite) TestEncryptPayloadToJWEShouldReturnJWETokenWhenValidPublicKeyIDAndJsonProvided() {
	pubKeyID := "tetherfi"
	keyData := models.KeyData{
		EncodingType: string(constants.PKIXPublicKey),
		EnvName:      "tetherfi",
	}
	jweRequest := request.JWERequest{
		Payload: map[string]interface{}{
			"key": "value",
		},
		PublicKeyId: pubKeyID,
	}
	suite.publickeyMappingConfig.EXPECT().GetKeyData(pubKeyID).Return(keyData, nil).Times(1)
	suite.cryptoUtil.EXPECT().GetPublicKey(suite.context, pubKeyID, constants.PKIXPublicKey).Return(suite.publicKey, nil).Times(1)
	encrypter, _ := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: suite.publicKey}, nil)
	suite.cryptoUtil.EXPECT().GetEncrypter(suite.context, suite.publicKey).Return(encrypter, nil).Times(1)
	_, cryptoError := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)
	suite.Nil(cryptoError)

}

func (suite CryptoServiceTestSuite) TestEncryptPayloadToJWEShouldThrowErrorWhenInvalidPubKeyIDProvided() {
	pubKeyID := "tetherfi"
	keyData := models.KeyData{
		EncodingType: string(constants.PKIXPublicKey),
		EnvName:      "tetherfi",
	}
	jweRequest := request.JWERequest{
		Payload: map[string]interface{}{
			"key": "value",
		},
		PublicKeyId: pubKeyID,
	}
	errorMsg := "invalid key type provided"
	suite.publickeyMappingConfig.EXPECT().GetKeyData(pubKeyID).Return(keyData, nil)
	suite.cryptoUtil.EXPECT().GetPublicKey(suite.context, pubKeyID, constants.PKIXPublicKey).Return(nil, errors.New(errorMsg))
	_, cryptoError := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)
	suite.Equal(&constants.InternalServerError, cryptoError)

}

func (suite CryptoServiceTestSuite) TestEncryptPayloadToJWEShouldThrowErrorWhenSomethingIsWrongWhileEncrypting() {
	pubKeyID := "tetherfi"
	keyData := models.KeyData{
		EncodingType: string(constants.PKIXPublicKey),
		EnvName:      "tetherfi",
	}
	jweRequest := request.JWERequest{
		Payload: map[string]interface{}{
			"key": "value",
		},
		PublicKeyId: pubKeyID,
	}
	errorMsg := "something went wrong"
	suite.publickeyMappingConfig.EXPECT().GetKeyData(pubKeyID).Return(keyData, nil)
	suite.cryptoUtil.EXPECT().GetPublicKey(suite.context, pubKeyID, constants.PKIXPublicKey).Return(suite.publicKey, nil)
	suite.cryptoUtil.EXPECT().GetEncrypter(suite.context, suite.publicKey).Return(nil, errors.New(errorMsg))
	_, cryptoError := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)
	suite.Equal(&constants.InternalServerError, cryptoError)

}

func (suite CryptoServiceTestSuite) TestEncryptPayloadToJWEShouldThrowBadRequestErrorWhenInvalidPublicKeyIdProvided() {
	pubKeyID := "invalid"
	jweRequest := request.JWERequest{
		Payload: map[string]interface{}{
			"key": "value",
		},
		PublicKeyId: pubKeyID,
	}
	errorMsg := "something went wrong"
	suite.publickeyMappingConfig.EXPECT().GetKeyData(pubKeyID).Return(models.KeyData{}, errors.New(errorMsg))
	_, cryptoError := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)
	suite.Equal(&constants.PayloadValidationError, cryptoError)

}

func (suite CryptoServiceTestSuite) TestShouldReturnJWEWhenValidJWTisProvided() {
	idToken := model.IdToken{
		Subject: "",
		UserId: "dummy-user",
		Email:  "",
	}
	keyData := models.KeyData{
		EncodingType: string(constants.PKCS1PublicKey),
		EnvName:      constants.PUBLIC_KEY,
	}
	jweRequest := request.JWERequest{
		PublicKeyId: constants.IDP_PUBLIC_KEY_ID,
		Payload:     idToken,
	}
	suite.publickeyMappingConfig.EXPECT().GetKeyData(constants.IDP_PUBLIC_KEY_ID).Return(keyData, nil)
	suite.cryptoUtil.EXPECT().GetPublicKey(suite.context, constants.PUBLIC_KEY, constants.PKCS1PublicKey).Return(suite.publicKey, nil)

	encrypter, _ := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: suite.publicKey}, nil)
	suite.cryptoUtil.EXPECT().GetEncrypter(suite.context, suite.publicKey).Return(encrypter, nil)

	actualJWE, _ := suite.cryptoService.EncryptPayloadToJWE(suite.context, jweRequest)

	suite.Equal(5, len(strings.Split(actualJWE.JWEToken, ".")))
}
