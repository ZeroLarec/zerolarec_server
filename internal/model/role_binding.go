package model

type Permission string

const (
	PermissionSecretGet         Permission = "secret.get"
	PermissionSecretUpdate      Permission = "secret.update"
	PermissionSecretDelete      Permission = "secret.delete"
	PermissionSecretGrantAccess Permission = "secret.grant_access"

	PermissionVaultGet          Permission = "vault.get"
	PermissionVaultUpdate       Permission = "vault.update"
	PermissionVaultDelete       Permission = "vault.delete"
	PermissionVaultListMembers  Permission = "vault.list_members"
	PermissionVaultAddMember    Permission = "vault.add_member"
	PermissionVaultRemoveMember Permission = "vault.remove_member"
	PermissionVaultGrantAccess  Permission = "vault.grant_access"
)

type Role struct {
	Permissions map[Permission]struct{}
}

var (
	RoleMember = Role{
		Permissions: map[Permission]struct{}{
			PermissionVaultGet:         {},
			PermissionVaultListMembers: {},
		},
	}
	RoleViewer = Role{
		Permissions: map[Permission]struct{}{
			PermissionSecretGet: {},

			PermissionVaultGet:         {},
			PermissionVaultListMembers: {},
		},
	}
	RoleEditor = Role{
		Permissions: map[Permission]struct{}{
			PermissionSecretGet:    {},
			PermissionSecretUpdate: {},
			PermissionSecretDelete: {},

			PermissionVaultGet:         {},
			PermissionVaultUpdate:      {},
			PermissionVaultDelete:      {},
			PermissionVaultListMembers: {},
		},
	}
	RoleAdmin = Role{
		Permissions: map[Permission]struct{}{
			PermissionSecretGet:         {},
			PermissionSecretUpdate:      {},
			PermissionSecretDelete:      {},
			PermissionSecretGrantAccess: {},

			PermissionVaultGet:          {},
			PermissionVaultUpdate:       {},
			PermissionVaultDelete:       {},
			PermissionVaultListMembers:  {},
			PermissionVaultAddMember:    {},
			PermissionVaultRemoveMember: {},
			PermissionVaultGrantAccess:  {},
		},
	}
)

type SubjectKind string

const (
	SubjectKindUser SubjectKind = "user"
)

type Subject struct {
	Kind      SubjectKind
	SubjectID string
}

type ResourceKind string

const (
	ResourceKindVault  ResourceKind = "vault"
	ResourceKindSecret ResourceKind = "secret"
)

type Resource struct {
	Kind       ResourceKind
	ResourceID string
}

type RoleBinding struct {
	RoleBindingID string
	Subject       Subject
	Resource      Resource
	Role          Role
}
