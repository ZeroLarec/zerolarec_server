package model

import "github.com/google/uuid"

type Secret struct {
	VaultID  string
	SecretID string

	Name        string
	Description string
	Data        map[string]SecretData
}

type SecretData struct {
	Name           string
	ProtectedValue []byte
}

func NewSecret(vaultID, name, description string, data map[string]SecretData) *Secret {
	return &Secret{
		VaultID:     vaultID,
		SecretID:    uuid.NewString(),
		Name:        name,
		Description: description,
		Data:        data,
	}
}
