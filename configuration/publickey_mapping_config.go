package configuration

import (
	"crypto-service/models"
	"errors"
)

type PublickeyMappingConfiguration interface {
	GetKeyData(keyId string) (models.KeyData, error)
}

type publickeyMappingConfiguration struct {
	publicKeyMapping map[string]models.KeyData
}

func (config publickeyMappingConfiguration) GetKeyData(keyId string) (models.KeyData, error) {
	if config.publicKeyMapping[keyId] != (models.KeyData{}) {
		return config.publicKeyMapping[keyId], nil
	} else {
		return models.KeyData{}, errors.New("publickey id is invalid")
	}
}

func NewPublickeyMappingConfiguration(publickeyMap map[string]models.KeyData) PublickeyMappingConfiguration {
	return publickeyMappingConfiguration{publickeyMap}
}
