package controller

import (
	"bytes"
	"crypto-service/constants"
	"crypto-service/mocks"
	"crypto-service/models/request"
	"crypto-service/models/response"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

type CryptoControllerTestSuite struct {
	suite.Suite
	mockCtrl         *gomock.Controller
	cryptoController CryptoController
	recorder         *httptest.ResponseRecorder
	context          *gin.Context
	cryptoService    *mocks.MockCryptoService
	cryptoUtil       *mocks.MockCryptoUtil
}

func TestCryptoControllerTestSuite(t *testing.T) {
	suite.Run(t, new(CryptoControllerTestSuite))
}

func (suite *CryptoControllerTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())
	suite.recorder = httptest.NewRecorder()
	suite.context, _ = gin.CreateTestContext(suite.recorder)
	suite.cryptoService = mocks.NewMockCryptoService(suite.mockCtrl)
	suite.cryptoUtil = mocks.NewMockCryptoUtil(suite.mockCtrl)
	suite.cryptoController = NewCryptoController(suite.cryptoService, suite.cryptoUtil)
}

func (suite *CryptoControllerTestSuite) TearDownTest() {
	suite.mockCtrl.Finish()
}

func (suite CryptoControllerTestSuite) TestShouldReturnBadRequestWhenCypherTextIsEmpty() {
	decryptRequest := request.DecryptRequest{}
	bytesRequest, _ := json.Marshal(decryptRequest)
	suite.context.Request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(string(bytesRequest)))
	suite.cryptoController.Decrypt(suite.context)

	suite.Equal(http.StatusBadRequest, suite.recorder.Code)
}

func (suite CryptoControllerTestSuite) TestShouldReturnDecryptedTextWhenDecryptionIsSuccessful() {
	decryptRequest := request.DecryptRequest{EncryptedText: "hello"}
	expectedResponse := response.DecryptResponse{DecryptedText: "decrypted_text"}
	bytesRequest, _ := json.Marshal(decryptRequest)
	suite.context.Request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(string(bytesRequest)))
	suite.cryptoService.EXPECT().Decrypt(suite.context, gomock.Any()).Return(response.DecryptResponse{DecryptedText: "decrypted_text"}, nil)
	suite.cryptoController.Decrypt(suite.context)
	bodyBytes, _ := ioutil.ReadAll(suite.recorder.Body)
	body := string(bodyBytes)
	expectedBody, _ := json.Marshal(expectedResponse)
	suite.Equal(string(expectedBody), body)
	suite.Equal(http.StatusOK, suite.recorder.Code)
}

func (suite CryptoControllerTestSuite) TestShouldReturnDecryptErrorWhenDecryptionFails() {
	decryptRequest := request.DecryptRequest{EncryptedText: "hello"}
	bytesRequest, _ := json.Marshal(decryptRequest)
	suite.context.Request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(string(bytesRequest)))

	suite.cryptoService.EXPECT().Decrypt(suite.context, gomock.Any()).Return(response.DecryptResponse{}, &constants.DecryptionError)
	suite.cryptoController.Decrypt(suite.context)

	suite.Equal(http.StatusInternalServerError, suite.recorder.Code)
}

func (suite CryptoControllerTestSuite) TestShouldReturnBadRequestErrorWhenDecodeErrorIsThrown() {
	decryptRequest := request.DecryptRequest{EncryptedText: "hello"}
	bytesRequest, _ := json.Marshal(decryptRequest)
	suite.context.Request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(string(bytesRequest)))

	suite.cryptoService.EXPECT().Decrypt(suite.context, "hello").Return(response.DecryptResponse{}, &constants.DecodeError)
	suite.cryptoController.Decrypt(suite.context)

	suite.Equal(http.StatusBadRequest, suite.recorder.Code)
}
