package service

import (
	"context"

	"github.com/ZeroLarec/zerolarec_server/internal/model"
)

type UserService interface {
	GetUser(ctx context.Context, userID string) (*model.User, error)
	GetUserByLogin(ctx context.Context, login string) (*model.User, error)
	CreateUser(ctx context.Context, login string) (*model.User, error)
	AddUserKeys(ctx context.Context, userID string, publicKey, privateKeyProtected, masterKeyHash []byte) error
	GetUserPublicKey(ctx context.Context, userID string) ([]byte, error)
	GetUserProtectedKeys(ctx context.Context, userID string) ([]byte, error)
}

type SecretService interface {
	ListSecrets(ctx context.Context, vaultID string, offset, limit int32) ([]*model.Secret, error)
	GetSecret(ctx context.Context, secretID string) (*model.Secret, error)
	CreateSecret(ctx context.Context, vaultID string, name, description string, data map[string]model.SecretData) (*model.Secret, error)
	UpdateSecret(ctx context.Context, secretID string, name, description string, data map[string]model.SecretData) (*model.Secret, error)
	DeleteSecret(ctx context.Context, secretID string) error
}

type VaultService interface {
	ListVaults(ctx context.Context, offset, limit int32) ([]*model.Vault, error)
	GetVault(ctx context.Context, vaultID string) (*model.Vault, error)
	CreateVault(ctx context.Context, userID string, userVaultKeyProtected []byte, name, description string) (*model.Vault, error)
	UpdateVault(ctx context.Context, vaultID, name, description string) (*model.Vault, error)
	DeleteVault(ctx context.Context, vaultID string) error

	GetProtectedVaultKey(ctx context.Context, vaultID string, userID string) ([]byte, error)
	IsMember(ctx context.Context, vaultID, userID string) (bool, error)
	ListMembers(ctx context.Context, vaultID string, offset, limit int32) ([]string, error)
	AddMember(ctx context.Context, vaultID, userID string, userVaultKeyProtected []byte) error
	RemoveMember(ctx context.Context, vaultID, userID string) error
}

type RoleBindingService interface {
	ListRoleBindings(ctx context.Context, subject *model.Subject, resource *model.Resource, offset, limit int32) ([]*model.RoleBinding, error)
	GetRoleBinding(ctx context.Context, roleBindingID string) (*model.RoleBinding, error)
	AddRoleBinding(ctx context.Context, subject model.Subject, resource model.Resource, role model.Role) (*model.RoleBinding, error)
	DeleteRoleBinding(ctx context.Context, roleBindingID string) error
	HaveAccess(ctx context.Context, userID string, resource model.Resource, permission model.Permission) (bool, error)
}

type AuthService interface {
	Login(ctx context.Context, login, password string) (string, error)
	Register(ctx context.Context, login, password string) (string, error)
	Authenticate(ctx context.Context, accessToken string) (string, error)
}
