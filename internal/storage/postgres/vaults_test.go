package postgres

import (
	"context"
	"testing"

	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"github.com/google/uuid"
)

func TestVaultStorage(t *testing.T) {
	ctx := context.Background()
	config := Config{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "mysecretpassword",
		DBName:   "postgres",
		UseTLS:   false,
	}
	store, err := NewStorage(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.db.Close()

	// Create test users
	ownerLogin := "owner"
	ownerPublicKey := []byte("owner-public-key")
	ownerPasswordHash := []byte("owner-password-hash")
	ownerPrivateKeyProtected := []byte("owner-private-key-protected")

	owner, err := store.CreateUser(ctx, ownerLogin, ownerPublicKey, ownerPasswordHash, ownerPrivateKeyProtected)
	if err != nil {
		t.Fatalf("Failed to create owner user: %v", err)
	}

	memberLogin := "member"
	memberPublicKey := []byte("member-public-key")
	memberPasswordHash := []byte("member-password-hash")
	memberPrivateKeyProtected := []byte("member-private-key-protected")

	member, err := store.CreateUser(ctx, memberLogin, memberPublicKey, memberPasswordHash, memberPrivateKeyProtected)
	if err != nil {
		t.Fatalf("Failed to create member user: %v", err)
	}

	notMemberLogin := "not-member"
	notMemberPublicKey := []byte("not-member-public-key")
	notMemberPasswordHash := []byte("not-member-password-hash")
	notMemberPrivateKeyProtected := []byte("not-member-private-key-protected")

	notMember, err := store.CreateUser(ctx, notMemberLogin, notMemberPublicKey, notMemberPasswordHash, notMemberPrivateKeyProtected)
	if err != nil {
		t.Fatalf("Failed to create not member user: %v", err)
	}

	t.Run("CreateVault", func(t *testing.T) {
		vaultName := "test-vault"
		vaultDescription := "Test vault description"
		vaultKeyProtected := []byte("vault-key-protected")

		vault, err := store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}
		if vault.VaultID == "" {
			t.Error("Expected non-empty VaultID")
		}
		if vault.Name != vaultName {
			t.Errorf("Expected name %q, got %q", vaultName, vault.Name)
		}
		if vault.Description != vaultDescription {
			t.Errorf("Expected description %q, got %q", vaultDescription, vault.Description)
		}
		if vault.CreatedAt.IsZero() {
			t.Error("Expected non-zero CreatedAt")
		}
		if vault.UpdatedAt.IsZero() {
			t.Error("Expected non-zero UpdatedAt")
		}

		// Verify vault member was created
		_, err = store.GetVaultKeyProtected(ctx, owner.UserID, vault.VaultID)
		if err != nil {
			t.Fatalf("Failed to get vault key protected: %v", err)
		}
	})

	t.Run("GetVault", func(t *testing.T) {
		vaultName := "test-vault-get"
		vaultDescription := "Test vault description for get"
		vaultKeyProtected := []byte("vault-key-protected")

		createdVault, err := store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}

		// Test getting vault
		vault, err := store.GetVault(ctx, owner.UserID, createdVault.VaultID)
		if err != nil {
			t.Fatalf("Failed to get vault: %v", err)
		}
		if vault.VaultID != createdVault.VaultID {
			t.Errorf("Expected VaultID %q, got %q", createdVault.VaultID, vault.VaultID)
		}
		if vault.Name != vaultName {
			t.Errorf("Expected name %q, got %q", vaultName, vault.Name)
		}
		if vault.Description != vaultDescription {
			t.Errorf("Expected description %q, got %q", vaultDescription, vault.Description)
		}

		// Test getting non-existent vault
		_, err = store.GetVault(ctx, owner.UserID, uuid.NewString())
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError, got %v", err)
		}

		// Test getting vault without membership
		_, err = store.GetVault(ctx, notMember.UserID, createdVault.VaultID)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}
	})

	t.Run("ListVaults", func(t *testing.T) {
		// Create multiple vaults
		vaultNames := []string{"List Vault 1", "List Vault 2", "List Vault 3"}
		vaultDescription := "Test vault description for list"
		vaultKeyProtected := []byte("vault-key-protected")

		for _, name := range vaultNames {
			_, err := store.CreateVault(ctx, owner.UserID, name, vaultDescription, vaultKeyProtected)
			if err != nil {
				t.Fatalf("Failed to create vault: %v", err)
			}
		}

		// Test listing vaults
		vaults, err := store.ListVaults(ctx, owner.UserID, 10, 0)
		if err != nil {
			t.Fatalf("Failed to list vaults: %v", err)
		}
		if len(vaults) < len(vaultNames) {
			t.Errorf("Expected at least %d vaults, got %d", len(vaultNames), len(vaults))
		}

		// Test listing vaults for non-member
		vaults, err = store.ListVaults(ctx, notMember.UserID, 10, 0)
		if err != nil {
			t.Fatalf("Failed to list vaults: %v", err)
		}
		if len(vaults) != 0 {
			t.Errorf("Expected 0 vaults for non-member, got %d", len(vaults))
		}

		// Test pagination
		vaults, err = store.ListVaults(ctx, owner.UserID, 2, 0)
		if err != nil {
			t.Fatalf("Failed to list vaults with limit: %v", err)
		}
		if len(vaults) > 2 {
			t.Errorf("Expected at most 2 vaults, got %d", len(vaults))
		}

		vaults, err = store.ListVaults(ctx, owner.UserID, 2, 2)
		if err != nil {
			t.Fatalf("Failed to list vaults with offset: %v", err)
		}
		if len(vaults) > 2 {
			t.Errorf("Expected at most 2 vaults, got %d", len(vaults))
		}
	})

	t.Run("UpdateVault", func(t *testing.T) {
		vaultName := "test-vault-update"
		vaultDescription := "Test vault description for update"
		vaultKeyProtected := []byte("vault-key-protected")

		createdVault, err := store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}

		// Test updating vault
		newName := "Updated Vault Name"
		newDescription := "Updated vault description"

		updatedVault, err := store.UpdateVault(ctx, owner.UserID, createdVault.VaultID, &newName, &newDescription)
		if err != nil {
			t.Fatalf("Failed to update vault: %v", err)
		}
		if updatedVault.Name != newName {
			t.Errorf("Expected name %q, got %q", newName, updatedVault.Name)
		}
		if updatedVault.Description != newDescription {
			t.Errorf("Expected description %q, got %q", newDescription, updatedVault.Description)
		}
		if !updatedVault.UpdatedAt.After(createdVault.UpdatedAt) {
			t.Error("Expected UpdatedAt to be after creation time")
		}

		// Test updating non-existent vault
		_, err = store.UpdateVault(ctx, owner.UserID, uuid.NewString(), &newName, &newDescription)
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError, got %v", err)
		}

		// Test updating vault without membership
		_, err = store.UpdateVault(ctx, notMember.UserID, createdVault.VaultID, &newName, &newDescription)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}
	})

	t.Run("DeleteVault", func(t *testing.T) {
		vaultName := "test-vault-delete"
		vaultDescription := "Test vault description for delete"
		vaultKeyProtected := []byte("vault-key-protected")

		createdVault, err := store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}

		// Test deleting vault
		err = store.DeleteVault(ctx, owner.UserID, createdVault.VaultID)
		if err != nil {
			t.Fatalf("Failed to delete vault: %v", err)
		}

		// Verify deletion
		_, err = store.GetVault(ctx, owner.UserID, createdVault.VaultID)
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError, got %v", err)
		}

		// Test deleting non-existent vault
		err = store.DeleteVault(ctx, owner.UserID, uuid.NewString())
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError, got %v", err)
		}

		// Test deleting vault without membership
		createdVault, err = store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}
		err = store.DeleteVault(ctx, notMember.UserID, createdVault.VaultID)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}
	})

	t.Run("VaultMembers", func(t *testing.T) {
		vaultName := "test-vault-members"
		vaultDescription := "Test vault description for members"
		vaultKeyProtected := []byte("vault-key-protected")

		createdVault, err := store.CreateVault(ctx, owner.UserID, vaultName, vaultDescription, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to create vault: %v", err)
		}

		// Verify owner is automatically a member
		_, err = store.GetVaultKeyProtected(ctx, owner.UserID, createdVault.VaultID)
		if err != nil {
			t.Fatalf("Failed to get vault key protected for owner: %v", err)
		}

		// Test listing members - should include owner
		members, err := store.ListVaultMembers(ctx, owner.UserID, createdVault.VaultID, 10, 0)
		if err != nil {
			t.Fatalf("Failed to list members: %v", err)
		}
		if len(members) != 1 {
			t.Errorf("Expected 1 member (owner), got %d", len(members))
		}

		// Test adding member
		err = store.AddVaultMember(ctx, owner.UserID, createdVault.VaultID, member.UserID, vaultKeyProtected)
		if err != nil {
			t.Fatalf("Failed to add member: %v", err)
		}

		// Verify member was added
		_, err = store.GetVaultKeyProtected(ctx, member.UserID, createdVault.VaultID)
		if err != nil {
			t.Fatalf("Failed to get vault key protected for member: %v", err)
		}

		// Test listing members - should now include both owner and member
		members, err = store.ListVaultMembers(ctx, owner.UserID, createdVault.VaultID, 10, 0)
		if err != nil {
			t.Fatalf("Failed to list members: %v", err)
		}
		if len(members) != 2 {
			t.Errorf("Expected 2 members (owner + member), got %d", len(members))
		}

		// Test adding existing member - should return AlreadyExistsError
		err = store.AddVaultMember(ctx, owner.UserID, createdVault.VaultID, member.UserID, vaultKeyProtected)
		if !storage.IsAlreadyExistsError(err) {
			t.Errorf("Expected AlreadyExistsError when adding existing member, got %v", err)
		}

		// Test deleting member
		err = store.RemoveVaultMember(ctx, owner.UserID, createdVault.VaultID, member.UserID)
		if err != nil {
			t.Fatalf("Failed to delete member: %v", err)
		}

		// Verify member was removed
		_, err = store.GetVaultKeyProtected(ctx, member.UserID, createdVault.VaultID)
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError after removing member, got %v", err)
		}

		// Test operations without permission
		err = store.AddVaultMember(ctx, member.UserID, createdVault.VaultID, notMember.UserID, vaultKeyProtected)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}

		_, err = store.ListVaultMembers(ctx, notMember.UserID, createdVault.VaultID, 10, 0)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}

		_, err = store.GetVaultKeyProtected(ctx, notMember.UserID, createdVault.VaultID)
		if !storage.IsNotFoundError(err) {
			t.Errorf("Expected NotFoundError, got %v", err)
		}

		err = store.RemoveVaultMember(ctx, notMember.UserID, createdVault.VaultID, owner.UserID)
		if !storage.IsNoAccessError(err) {
			t.Errorf("Expected NoAccessError, got %v", err)
		}
	})
}
