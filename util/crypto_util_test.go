package util

import (
	"crypto-service/constants"
	"github.com/gin-gonic/gin"
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
	suite.context, _ = gin.CreateTestContext(httptest.NewRecorder())
	suite.context.Request, _ = http.NewRequest("GET", "dummyUrl", nil)
	err := os.Setenv(constants.PASSWORD_PRIVATE_KEY, string(passwordPrivateKey))
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
