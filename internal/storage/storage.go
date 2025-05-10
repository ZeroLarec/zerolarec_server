package storage

import (
	"context"
	"time"
)

type Storage interface {
	UserStorage
	AccessRuleStorage
	VaultStorage
	SecretStorage
}

type UserStorage interface {
	GetUser(ctx context.Context, userID string) (user *User, err error)
	GetUserByLogin(ctx context.Context, login string) (user *User, err error)
	GetUserPasswordHashByLogin(ctx context.Context, login string) (passwordHash []byte, err error)
	CreateUser(ctx context.Context, login string, publicKey, passwordHash []byte) (user *User, err error)
	UpdateUser(ctx context.Context, userID string, login *string) (user *User, err error)
	DeleteUser(ctx context.Context, userID string) (err error)
}

type AccessRuleStorage interface {
	ListAccessRules(ctx context.Context, callerID, vaultID string, limit, offset int) (accessRules []*AccessRule, err error)
	GetAccessRule(ctx context.Context, callerID, accessRuleID string) (accessRule *AccessRule, err error)
	CreateAccessRule(
		ctx context.Context,
		callerID string,
		userID string,
		vaultID string,
		secretID string,
		description string,
		permissions []Permission,
		expiresAt time.Time,
	) (accessRule *AccessRule, err error)
	UpdateAccessRule(
		ctx context.Context,
		callerID string,
		accessRuleID string,
		description *string,
		permissions *[]Permission,
		expiresAt *time.Time,
	) (accessRule *AccessRule, err error)
	DeleteAccessRule(ctx context.Context, callerID string, accessRuleID string) (err error)
}

type VaultStorage interface {
	ListVaults(ctx context.Context, callerID string, limit, offset int) (vaults []*Vault, err error)
	GetVault(ctx context.Context, callerID, vaultID string) (vault *Vault, err error)
	CreateVault(ctx context.Context, callerID, name, description string, vaultKeyProtected []byte) (vault *Vault, err error)
	UpdateVault(ctx context.Context, callerID, vaultID string, name, description *string) (vault *Vault, err error)
	DeleteVault(ctx context.Context, callerID, vaultID string) (err error)

	ListVaultMembers(ctx context.Context, callerID, vaultID string, limit, offset int) (vaultMembers []*User, err error)
	AddVaultMember(ctx context.Context, callerID, vaultID, userID string, vaultKeyProtected []byte) (err error)
	RemoveVaultMember(ctx context.Context, callerID, vaultID, userID string) (err error)
	GetVaultKeyProtected(ctx context.Context, callerID, vaultID string) (vaultKeyProtected []byte, err error)
}

type SecretStorage interface {
	ListSecrets(ctx context.Context, callerID, vaultID string, limit, offset int) (secrets []*Secret, err error)
	GetSecret(ctx context.Context, callerID, vaultID, secretID string) (secret *Secret, err error)
	CreateSecret(ctx context.Context, callerID, vaultID, name, description string, keyValues map[string][]byte) (secret *Secret, err error)
	UpdateSecret(ctx context.Context, callerID, vaultID, secretID string, name, description *string, keyValues *map[string][]byte) (secret *Secret, err error)
	DeleteSecret(ctx context.Context, callerID, vaultID, secretID string) (err error)
}
