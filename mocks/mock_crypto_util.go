// Code generated by MockGen. DO NOT EDIT.
// Source: util/crypto_util.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	constants "crypto-service/constants"
	rsa "crypto/rsa"
	gin "github.com/gin-gonic/gin"
	golaerror "github.com/gola-glitch/gola-utils/golaerror"
	model "github.com/gola-glitch/gola-utils/model"
	gomock "github.com/golang/mock/gomock"
	go_jose_v2 "gopkg.in/square/go-jose.v2"
	reflect "reflect"
)

// MockCryptoUtil is a mock of CryptoUtil interface
type MockCryptoUtil struct {
	ctrl     *gomock.Controller
	recorder *MockCryptoUtilMockRecorder
}

// MockCryptoUtilMockRecorder is the mock recorder for MockCryptoUtil
type MockCryptoUtilMockRecorder struct {
	mock *MockCryptoUtil
}

// NewMockCryptoUtil creates a new mock instance
func NewMockCryptoUtil(ctrl *gomock.Controller) *MockCryptoUtil {
	mock := &MockCryptoUtil{ctrl: ctrl}
	mock.recorder = &MockCryptoUtilMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockCryptoUtil) EXPECT() *MockCryptoUtilMockRecorder {
	return m.recorder
}

// DecodeJwtToken mocks base method
func (m *MockCryptoUtil) DecodeJwtToken(jwtToken string) (model.IdToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecodeJwtToken", jwtToken)
	ret0, _ := ret[0].(model.IdToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecodeJwtToken indicates an expected call of DecodeJwtToken
func (mr *MockCryptoUtilMockRecorder) DecodeJwtToken(jwtToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecodeJwtToken", reflect.TypeOf((*MockCryptoUtil)(nil).DecodeJwtToken), jwtToken)
}

// Decrypt mocks base method
func (m *MockCryptoUtil) Decrypt(key *rsa.PrivateKey, encryptedText string, ctx context.Context) (string, *golaerror.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decrypt", key, encryptedText, ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(*golaerror.Error)
	return ret0, ret1
}

// Decrypt indicates an expected call of Decrypt
func (mr *MockCryptoUtilMockRecorder) Decrypt(key, encryptedText, ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decrypt", reflect.TypeOf((*MockCryptoUtil)(nil).Decrypt), key, encryptedText, ctx)
}

// GetEncryptor mocks base method
func (m *MockCryptoUtil) GetEncryptor(ctx *gin.Context, publicKey *rsa.PublicKey) (go_jose_v2.Encrypter, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEncryptor", ctx, publicKey)
	ret0, _ := ret[0].(go_jose_v2.Encrypter)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEncryptor indicates an expected call of GetEncryptor
func (mr *MockCryptoUtilMockRecorder) GetEncryptor(ctx, publicKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEncryptor", reflect.TypeOf((*MockCryptoUtil)(nil).GetEncryptor), ctx, publicKey)
}

// GetPrivateKey mocks base method
func (m *MockCryptoUtil) GetPrivateKey(ctx *gin.Context, key string) (*rsa.PrivateKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrivateKey", ctx, key)
	ret0, _ := ret[0].(*rsa.PrivateKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPrivateKey indicates an expected call of GetPrivateKey
func (mr *MockCryptoUtilMockRecorder) GetPrivateKey(ctx, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrivateKey", reflect.TypeOf((*MockCryptoUtil)(nil).GetPrivateKey), ctx, key)
}

// GetPublicKey mocks base method
func (m *MockCryptoUtil) GetPublicKey(ctx *gin.Context, key string, keyType constants.PublicKeyType) (*rsa.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPublicKey", ctx, key, keyType)
	ret0, _ := ret[0].(*rsa.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKey indicates an expected call of GetPublicKey
func (mr *MockCryptoUtilMockRecorder) GetPublicKey(ctx, key, keyType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKey", reflect.TypeOf((*MockCryptoUtil)(nil).GetPublicKey), ctx, key, keyType)
}

// EncodePayloadToJWTToken mocks base method
func (m *MockCryptoUtil) EncodePayloadToJWTToken(payload string, key *rsa.PrivateKey) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncodePayloadToJWTToken", payload, key)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncodePayloadToJWTToken indicates an expected call of EncodePayloadToJWTToken
func (mr *MockCryptoUtilMockRecorder) EncodePayloadToJWTToken(payload, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncodePayloadToJWTToken", reflect.TypeOf((*MockCryptoUtil)(nil).EncodePayloadToJWTToken), payload, key)
}
