package model

import "github.com/google/uuid"

type Vault struct {
	VaultID     string
	Name        string
	Description string
}

func NewVault(name, description string) *Vault {
	return &Vault{
		VaultID:     uuid.NewString(),
		Name:        name,
		Description: description,
	}
}
