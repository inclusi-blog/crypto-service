package configuration

import (
	"crypto-service/models"
	"github.com/stretchr/testify/suite"
	"testing"
)

type PublickeyMappingConfigurationTestSuite struct {
	suite.Suite
}

func TestPublickeyMappingConfigurationTestSuite(t *testing.T) {
	suite.Run(t, new(PublickeyMappingConfigurationTestSuite))
}

func (suite PublickeyMappingConfigurationTestSuite) TestGetEnvNameShouldGetPublickeyMappingConfigurations() {
	configuration := NewPublickeyMappingConfiguration(map[string]models.KeyData{
		"tetherfi": {
			EnvName:      "value",
			EncodingType: "value2",
		},
	})

	value, _ := configuration.GetKeyData("tetherfi")
	suite.Equal("value", value.EnvName)
	suite.Equal("value2", value.EncodingType)
}

func (suite PublickeyMappingConfigurationTestSuite) TestGetEnvNameShouldThrowErrorIfInvalidKeyIsPassed() {
	configuration := NewPublickeyMappingConfiguration(map[string]models.KeyData{
		"tetherfi": {
			EnvName:      "value",
			EncodingType: "value2",
		},
	})
	_, err := configuration.GetKeyData("key1")
	suite.Error(err)
}
