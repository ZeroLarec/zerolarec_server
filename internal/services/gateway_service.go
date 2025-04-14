package service

import (
	"context"
	"fmt"

	"github.com/ZeroLarec/zerolarec_server/internal/model"
)

type GatewayServiceImpl struct {
	userService        UserService
	secretService      SecretService
	vaultService       VaultService
	roleBindingService RoleBindingService
	authService        AuthService
}

func NewGatewayServiceImpl(
	userService UserService,
	secretService SecretService,
	vaultService VaultService,
	roleBindingService RoleBindingService,
	authService AuthService,
) *GatewayServiceImpl {
	return &GatewayServiceImpl{
		userService:        userService,
		secretService:      secretService,
		vaultService:       vaultService,
		roleBindingService: roleBindingService,
		authService:        authService,
	}
}

func (s *GatewayServiceImpl) Register(ctx context.Context, login, password string) (string, *model.User, error) {
	user, err := s.userService.CreateUser(ctx, login)
	if err != nil {
		return "", nil, fmt.Errorf("create user: %w", err)
	}

	accessToken, err := s.authService.Register(ctx, login, password)
	if err != nil {
		return "", nil, fmt.Errorf("register: %w", err)
	}

	return accessToken, user, nil
}

func (s *GatewayServiceImpl) Login(ctx context.Context, login, password string) (string, *model.User, error) {
	accessToken, err := s.authService.Login(ctx, login, password)
	if err != nil {
		return "", nil, fmt.Errorf("login: %w", err)
	}

	user, err := s.userService.GetUserByLogin(ctx, login)
	if err != nil {
		return "", nil, fmt.Errorf("get user by login: %w", err)
	}

	return accessToken, user, nil
}

func (s *GatewayServiceImpl) GetUser(ctx context.Context, userID string) (*model.User, error) {
	return s.userService.GetUser(ctx, userID)
}

func (s *GatewayServiceImpl) AddUserKeys(ctx context.Context, callerUserID string, publicKey, privateKeyProtected, masterKeyHash []byte) error {
	return s.userService.AddUserKeys(ctx, callerUserID, publicKey, privateKeyProtected, masterKeyHash)
}

func (s *GatewayServiceImpl) GetUserPublicKey(ctx context.Context, userID string) ([]byte, error) {
	return s.userService.GetUserPublicKey(ctx, userID)
}

func (s *GatewayServiceImpl) GetUserProtectedKeys(ctx context.Context, callerUserID string) ([]byte, error) {
	return s.userService.GetUserProtectedKeys(ctx, callerUserID)
}

func (s *GatewayServiceImpl) GetProtectedVaultKey(ctx context.Context, vaultID, callerUserID string) ([]byte, error) {
	isMember, err := s.vaultService.IsMember(ctx, vaultID, callerUserID)
	if err != nil {
		return nil, fmt.Errorf("check vault membership: %w", err)
	}

	if !isMember {
		return nil, fmt.Errorf("user must be member of vault")
	}

	return s.vaultService.GetProtectedVaultKey(ctx, callerUserID, vaultID)
}

func (s *GatewayServiceImpl) ListSecrets(ctx context.Context, callerUserID, vaultID string, offset, limit int32) ([]*model.Secret, error) {
	secrets, err := s.secretService.ListSecrets(ctx, vaultID, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	var resultSecrets []*model.Secret
	for _, secret := range secrets {
		haveAccess, err := s.roleBindingService.HaveAccess(
			ctx,
			callerUserID,
			model.Resource{
				Kind:       model.ResourceKindSecret,
				ResourceID: secret.SecretID,
			},
			model.PermissionSecretGet,
		)
		if err != nil {
			return nil, fmt.Errorf("check access: %w", err)
		}

		if haveAccess {
			resultSecrets = append(resultSecrets, secret)
		}
	}

	return resultSecrets, nil
}

func (s *GatewayServiceImpl) GetSecret(ctx context.Context, callerUserID, secretID string) (*model.Secret, error) {
	haveAccess, err := s.roleBindingService.HaveAccess(
		ctx,
		callerUserID,
		model.Resource{
			Kind:       model.ResourceKindSecret,
			ResourceID: secretID,
		},
		model.PermissionSecretGet,
	)
	if err != nil {
		return nil, fmt.Errorf("check access: %w", err)
	}

	if !haveAccess {
		return nil, fmt.Errorf("user have not permission to get secret")
	}

	return s.secretService.GetSecret(ctx, secretID)
}

func (s *GatewayServiceImpl) CreateSecret(ctx context.Context, callerUserID, vaultID string, name, description string, data map[string]model.SecretData) (*model.Secret, error) {
	haveAccess, err := s.roleBindingService.HaveAccess(
		ctx,
		callerUserID,
		model.Resource{
			Kind:       model.ResourceKindVault,
			ResourceID: vaultID,
		},
		model.PermissionVaultUpdate,
	)
	if err != nil {
		return nil, fmt.Errorf("check access: %w", err)
	}

	if !haveAccess {
		return nil, fmt.Errorf("user have not permission to update vault")
	}

	secret, err := s.secretService.CreateSecret(ctx, vaultID, name, description, data)
	if err != nil {
		return nil, fmt.Errorf("create secret: %w", err)
	}

	return secret, nil
}

func (s *GatewayServiceImpl) UpdateSecret(ctx context.Context, callerUserID, secretID string, name, description string, data map[string]model.SecretData) (*model.Secret, error) {
	haveAccess, err := s.roleBindingService.HaveAccess(
		ctx,
		callerUserID,
		model.Resource{
			Kind:       model.ResourceKindSecret,
			ResourceID: secretID,
		},
		model.PermissionSecretUpdate,
	)
	if err != nil {
		return nil, fmt.Errorf("check access: %w", err)
	}

	if !haveAccess {
		return nil, fmt.Errorf("user have not permission to update secret")
	}

	return s.secretService.UpdateSecret(ctx, secretID, name, description, data)
}

func (s *GatewayServiceImpl) DeleteSecret(ctx context.Context, callerUserID, secretID string) error {
	haveAccess, err := s.roleBindingService.HaveAccess(
		ctx,
		callerUserID,
		model.Resource{
			Kind:       model.ResourceKindSecret,
			ResourceID: secretID,
		},
		model.PermissionSecretDelete,
	)
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}

	if !haveAccess {
		return fmt.Errorf("user have not permission to delete secret")
	}

	return s.secretService.DeleteSecret(ctx, secretID)
}

func (s *GatewayServiceImpl) ListVaults(ctx context.Context, callerUserID string, offset, limit int32) ([]*model.Vault, error) {
	vaults, err := s.vaultService.ListVaults(ctx, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}

	var resultVaults []*model.Vault
	for _, vault := range vaults {
		haveAccess, err := s.roleBindingService.HaveAccess(
			ctx,
			callerUserID,
			model.Resource{
				Kind:       model.ResourceKindVault,
				ResourceID: vault.VaultID,
			},
			model.PermissionVaultGet,
		)
		if err != nil {
			return nil, fmt.Errorf("check access: %w", err)
		}

		if haveAccess {
			resultVaults = append(resultVaults, vault)
		}
	}

	return resultVaults, nil
}
