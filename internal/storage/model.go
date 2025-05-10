package storage

import (
	"time"
)

type Vault struct {
	VaultID     string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Secret struct {
	SecretID    string
	VaultID     string
	Name        string
	Description string
	KeyValues   map[string][]byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type User struct {
	UserID    string
	Login     string
	PublicKey []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type VaultMember struct {
	VaultID   string
	UserID    string
	CreatedAt time.Time
}

type Permission string

const (
	PermissionSecretCreate      Permission = "secret.create"
	PermissionSecretGet         Permission = "secret.get"
	PermissionSecretUpdate      Permission = "secret.update"
	PermissionSecretDelete      Permission = "secret.delete"
	PermissionSecretGrantAccess Permission = "secret.grant_access"

	PermissionVaultUpdate        Permission = "vault.update"
	PermissionVaultDelete        Permission = "vault.delete"
	PermissionVaultManageMembers Permission = "vault.manage_members"
	PermissionVaultGrantAccess   Permission = "vault.grant_access"
)

var (
	PermissionSetViewer = []Permission{
		PermissionSecretGet,
	}
	PermissionSetEditor = append(PermissionSetViewer,
		PermissionSecretCreate,
		PermissionSecretUpdate,
		PermissionSecretDelete,

		PermissionVaultUpdate,
		PermissionVaultDelete,
	)
	PermissionSetAdmin = append(PermissionSetEditor,
		PermissionSecretGrantAccess,
		PermissionVaultManageMembers,
		PermissionVaultGrantAccess,
	)
)

type AccessRule struct {
	AccessRuleID string
	UserID       string
	VaultID      string
	SecretID     string
	Description  string
	Permissions  []Permission
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
