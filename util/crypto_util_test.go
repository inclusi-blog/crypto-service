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
	passwordPrivateKey, _ := ioutil.ReadFile(constants.PASSWORD_PRIVATE_KEY_FILE)
	privateKey, _ := ioutil.ReadFile(constants.PRIVATE_FILE)
	publicKey, _ := ioutil.ReadFile(constants.PUBLIC_FILE)
	suite.context, _ = gin.CreateTestContext(httptest.NewRecorder())
	suite.context.Request, _ = http.NewRequest("GET", "dummyUrl", nil)
	err := os.Setenv(constants.PASSWORD_PRIVATE_KEY, string(passwordPrivateKey))
	suite.Nil(err)
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
