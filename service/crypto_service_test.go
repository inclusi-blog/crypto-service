package service

import (
	"crypto-service/constants"
	"crypto-service/mocks"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"
)

type CryptoServiceTestSuite struct {
	suite.Suite
	context       *gin.Context
	mockCtrl      *gomock.Controller
	cryptoUtil    *mocks.MockCryptoUtil
	cryptoService CryptoService
	publicKey     *rsa.PublicKey
	privateKey    *rsa.PrivateKey
}

func TestCryptoServiceTestSuite(t *testing.T) {
	suite.Run(t, new(CryptoServiceTestSuite))
}

func (suite *CryptoServiceTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())
	suite.cryptoUtil = mocks.NewMockCryptoUtil(suite.mockCtrl)
	suite.cryptoService = NewCryptoService(suite.cryptoUtil)
	suite.context, _ = gin.CreateTestContext(httptest.NewRecorder())
	suite.context.Request, _ = http.NewRequest("GET", "some-url", nil)
}

func (suite *CryptoServiceTestSuite) SetupSuite() {
	suite.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	suite.publicKey = &suite.privateKey.PublicKey
}

func (suite *CryptoServiceTestSuite) TearDownTest() {
	suite.mockCtrl.Finish()
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
