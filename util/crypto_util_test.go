package util

import (
	"crypto-service/constants"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gola-glitch/gola-utils/model"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type CryptoUtilTestSuite struct {
	suite.Suite
	cryptoUtil CryptoUtil
	context    *gin.Context
}

func TestCryptoUtilTestSuite(t *testing.T) {
	suite.Run(t, new(CryptoUtilTestSuite))
}

func (suite *CryptoUtilTestSuite) SetupSuite() {
	publicKey, _ := ioutil.ReadFile(constants.PUBLIC_FILE)
	privateKey, _ := ioutil.ReadFile(constants.PRIVATE_FILE)
	passwordPrivateKey, _ := ioutil.ReadFile(constants.PASSWORD_PRIVATE_KEY_FILE)
	passwordPublicKey, _ := ioutil.ReadFile(constants.PASSWORD_PUBLIC_KEY_FILE)
	suite.context, _ = gin.CreateTestContext(httptest.NewRecorder())
	suite.context.Request, _ = http.NewRequest("GET", "dummyUrl", nil)
	err := os.Setenv(constants.PASSWORD_PRIVATE_KEY, string(passwordPrivateKey))
	suite.Nil(err)
	_ = os.Setenv("SOME_RSA_KEY", string(passwordPublicKey))
	_ = os.Setenv("SOME_RSA_KEY_WITH_INVALID_VALUE", "invalid key will error")
	err = os.Setenv(constants.PRIVATE_KEY, string(privateKey))
	suite.Nil(err)
	err = os.Setenv(constants.PUBLIC_KEY, string(publicKey))
	suite.Nil(err)
}

func (suite *CryptoUtilTestSuite) SetupTest() {
	suite.cryptoUtil = NewCryptoUtil()
}

func (suite CryptoUtilTestSuite) TestShouldReturnErrorWhenDecodingFailsForGivenInput() {
	privateKey, _ := suite.cryptoUtil.GetPrivateKey(suite.context, constants.PASSWORD_PRIVATE_KEY)
	_, err := suite.cryptoUtil.Decrypt(privateKey, "encrypted_text", suite.context)
	suite.NotNil(err)
}

func (suite CryptoUtilTestSuite) TestShouldReturnErrorWhenAlgorithmDecryptionFails() {
	privateKey, _ := suite.cryptoUtil.GetPrivateKey(suite.context, constants.PASSWORD_PRIVATE_KEY)
	_, err := suite.cryptoUtil.Decrypt(privateKey, "aGVsbG8=", suite.context)
	suite.NotNil(err)
}

func (suite CryptoUtilTestSuite) TestEncodePayloadToJWTTokenShouldReturnErrorForInvalidJSONFormat() {
	jweToken := "abc"
	key, _ := suite.cryptoUtil.GetPrivateKey(suite.context, constants.PRIVATE_KEY)
	_, err := suite.cryptoUtil.EncodePayloadToJWTToken(jweToken, key)
	expectedError := errors.New("invalid JSON")
	suite.Equal(expectedError, err)
}

func (suite CryptoUtilTestSuite) TestEncodePayloadToJWTTokenShouldEncodePayloadAndReturnSamePayloadAfterDecode() {
	//encode to JWT
	payload, _ := json.Marshal(map[string]interface{}{
		"subject":  "6d41e7ad-dc94-488a-8cd8-795dc36c614c",
		"userId":   "6d41e7ad-dc94-488a-8cd8-795dc36c614c",
		"username": "",
		"at_hash":  "",
		"email":    "",
	})

	key, _ := suite.cryptoUtil.GetPrivateKey(suite.context, constants.PRIVATE_KEY)
	idTokenJWT, err := suite.cryptoUtil.EncodePayloadToJWTToken(string(payload), key)
	//Decode from JWT
	idTokenModel, _ := suite.cryptoUtil.DecodeJwtToken(idTokenJWT)
	//Check
	expectedToken := model.IdToken{
		UserId:          "6d41e7ad-dc94-488a-8cd8-795dc36c614c",
		Username:        "",
		Email:           "",
		Subject:         "6d41e7ad-dc94-488a-8cd8-795dc36c614c",
		AccessTokenHash: "",
	}
	suite.Equal(expectedToken, idTokenModel)
	suite.Nil(err)
}

func (suite CryptoUtilTestSuite) TestShouldDecryptJWTAndReturnIdToken() {
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IiIsInN1YiI6IjZkNDFlN2FkLWRjOTQtNDg4YS04Y2Q4LTc5NWRjMzZjNjE0YyIsInVzZXJJZCI6IjZkNDFlN2FkLWRjOTQtNDg4YS04Y2Q4LTc5NWRjMzZjNjE0YyIsImF0X2hhc2giOiJ1UHN3bWxSS0R4eFFkTzFhUmJNbDN3In0.0Crf0GNhayiDJO3gVonRkMwUMDHmdDyCVSv306gwWwM"

	idTokenModel, err := suite.cryptoUtil.DecodeJwtToken(jwtToken)
	expectedToken := model.IdToken{
		Email:           "",
		Subject:         "",
		UserId:          "6d41e7ad-dc94-488a-8cd8-795dc36c614c",
		AccessTokenHash: "uPswmlRKDxxQdO1aRbMl3w",
	}
	suite.Equal(expectedToken, idTokenModel)
	suite.Nil(err)
}

func (suite CryptoUtilTestSuite) TestShouldReturnErrorForInvalidJwtTokenFormat() {
	jwtToken := "a.b"
	_, err := suite.cryptoUtil.DecodeJwtToken(jwtToken)
	expectedError := errors.New("invalid token format")
	suite.Equal(expectedError, err)
}

func (suite CryptoUtilTestSuite) TestShouldReturnErrorForValidFormatButNotBase64Encoded() {
	jwtToken := "a.b.c"
	_, err := suite.cryptoUtil.DecodeJwtToken(jwtToken)
	expectedError := base64.CorruptInputError(1)
	suite.Equal(expectedError, err)
}

func (suite CryptoUtilTestSuite) TestShouldReturnPublicKeyForCorrectFilePathAndPKCS1Type() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, constants.PUBLIC_KEY, constants.PKIXPublicKey)
	suite.Nil(err)
}

func (suite CryptoUtilTestSuite) TestShouldThrowErrorForInvalidKeyType() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, constants.PUBLIC_KEY, "loltype")
	suite.Error(err)
	suite.Equal("invalid key type provided", err.Error())
}

func (suite CryptoUtilTestSuite) TestShouldReturnPublicKeyForCorrectFilePathAndPKIXType() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, "SOME_RSA_KEY", constants.PKIXPublicKey)
	suite.Nil(err)
}

func (suite CryptoUtilTestSuite) TestShouldThrowErrorForInvalidKeyId() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, "SOME_INVALID_KEY", constants.PKIXPublicKey)
	suite.Error(err)
	suite.Equal("no env variable found", err.Error())
}

func (suite CryptoUtilTestSuite) TestShouldThrowErrorWhenKeyIsNotPem() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, "SOME_RSA_KEY_WITH_INVALID_VALUE", constants.PKIXPublicKey)
	suite.Error(err)
	suite.Equal("public key not found", err.Error())

}

func (suite CryptoUtilTestSuite) TestShouldThrowErrorWhenKeyIsOfInvalidFormat() {
	_, err := suite.cryptoUtil.GetPublicKey(suite.context, "SOME_RSA_KEY", constants.PKCS1PublicKey)
	suite.Error(err)
}

func (suite CryptoUtilTestSuite) TestShouldNotReturnErrorIfValidPublicKeyIsPassed() {
	publicKey, _ := suite.cryptoUtil.GetPublicKey(suite.context, constants.PUBLIC_KEY, constants.PKIXPublicKey)
	_, encrypterError := suite.cryptoUtil.GetEncryptor(suite.context, publicKey)

	suite.Nil(encrypterError)
}

func (suite CryptoUtilTestSuite) TestShouldReturnErrorIfInvalidPublicKeyIsPassed() {
	_, encrypterError := suite.cryptoUtil.GetEncryptor(suite.context, nil)
	suite.NotNil(encrypterError)
}
