package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"github.com/google/uuid"
)

var _ storage.VaultStorage = (*PostgresStorage)(nil)

func (s *PostgresStorage) ListVaults(ctx context.Context, callerID string, limit, offset int) ([]*storage.Vault, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	vaults, err := s.listAccessibleVaults(ctx, tx, callerID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listAccessibleVaults: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return vaults, nil
}

func (s *PostgresStorage) listAccessibleVaults(ctx context.Context, tx *sql.Tx, callerID string, limit, offset int) ([]*storage.Vault, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT v.id, v.name, v.description, v.created_at, v.updated_at
		FROM vaults v
		JOIN vault_members vm ON vm.vault_id = v.id
		WHERE vm.user_id = $1
		ORDER BY v.created_at DESC
		LIMIT $2 OFFSET $3
	`, callerID, limit, offset)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("execute listAccessibleVaults query: %w", err))
	}
	defer rows.Close()

	var vaults []*storage.Vault
	for rows.Next() {
		var vault storage.Vault
		err := rows.Scan(&vault.VaultID, &vault.Name, &vault.Description, &vault.CreatedAt, &vault.UpdatedAt)
		if err != nil {
			return nil, storage.NewInternalError(fmt.Errorf("scan vault: %w", err))
		}
		vaults = append(vaults, &vault)
	}

	if err := rows.Err(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("iterate vaults: %w", err))
	}

	return vaults, nil
}

func (s *PostgresStorage) GetVault(ctx context.Context, callerID, vaultID string) (*storage.Vault, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	vault, err := s.getVault(ctx, tx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("getVault: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return vault, nil
}

func (s *PostgresStorage) getVault(ctx context.Context, tx *sql.Tx, vaultID string) (*storage.Vault, error) {
	var vault storage.Vault
	err := tx.QueryRowContext(ctx, `
		SELECT v.id, v.name, v.description, v.created_at, v.updated_at
		FROM vaults v
		WHERE v.id = $1
	`, vaultID).Scan(&vault.VaultID, &vault.Name, &vault.Description, &vault.CreatedAt, &vault.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan vault: %w", err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan vault: %w", err))
	}
	return &vault, nil
}

func (s *PostgresStorage) CreateVault(ctx context.Context, callerID string, name, description string, vaultKeyProtected []byte) (*storage.Vault, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	vault := &storage.Vault{
		VaultID:     uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.createVault(ctx, tx, vault); err != nil {
		return nil, fmt.Errorf("createVault: %w", err)
	}

	member := &storage.VaultMember{
		UserID:    callerID,
		VaultID:   vault.VaultID,
		CreatedAt: time.Now(),
	}

	if err := s.createVaultMember(ctx, tx, member, vaultKeyProtected); err != nil {
		return nil, fmt.Errorf("createVaultMember: %w", err)
	}

	if err := s.createAccessRule(ctx, tx, &storage.AccessRule{
		AccessRuleID: uuid.NewString(),
		UserID:       callerID,
		VaultID:      vault.VaultID,
		SecretID:     "",
		Description:  "Owner of the vault",
		Permissions:  storage.PermissionSetAdmin,
		ExpiresAt:    time.Now().Add(time.Hour * 24 * 365 * 100),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("createAccessRule: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return vault, nil
}

func (s *PostgresStorage) createVault(ctx context.Context, tx *sql.Tx, vault *storage.Vault) error {
	query := `
		INSERT INTO vaults (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := tx.ExecContext(ctx, query, vault.VaultID, vault.Name, vault.Description, vault.CreatedAt, vault.UpdatedAt)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("insert vault: %w", err))
	}
	return nil
}

func (s *PostgresStorage) UpdateVault(ctx context.Context, callerID, vaultID string, name, description *string) (*storage.Vault, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	vault, err := s.getVault(ctx, tx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("getVault: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	if name != nil {
		vault.Name = *name
	}
	if description != nil {
		vault.Description = *description
	}
	vault.UpdatedAt = time.Now()

	if err := s.updateVault(ctx, tx, vault); err != nil {
		return nil, fmt.Errorf("updateVault: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return vault, nil
}

func (s *PostgresStorage) updateVault(ctx context.Context, tx *sql.Tx, vault *storage.Vault) error {
	query := `
		UPDATE vaults SET name = $2, description = $3, updated_at = $4 WHERE id = $1
	`
	_, err := tx.ExecContext(ctx, query, vault.VaultID, vault.Name, vault.Description, vault.UpdatedAt)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("update vault: %w", err))
	}
	return nil
}

func (s *PostgresStorage) DeleteVault(ctx context.Context, callerID, vaultID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVault(ctx, tx, vaultID); err != nil {
		return fmt.Errorf("getVault: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return fmt.Errorf("getVaultMember: %w", err)
	}

	if err := s.deleteVault(ctx, tx, vaultID); err != nil {
		return fmt.Errorf("deleteVault: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) deleteVault(ctx context.Context, tx *sql.Tx, vaultID string) error {
	query := `
		DELETE FROM vaults WHERE id = $1
	`
	res, err := tx.ExecContext(ctx, query, vaultID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("delete vault: %w", err))
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("get rows affected: %w", err))
	}
	if rows == 0 {
		return storage.NewInternalError(fmt.Errorf("vault not found"))
	}
	return nil
}

func (s *PostgresStorage) ListVaultMembers(ctx context.Context, callerID, vaultID string, limit, offset int) ([]*storage.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	members, err := s.listVaultMembers(ctx, tx, vaultID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list vault members: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return members, nil
}

func (s *PostgresStorage) listVaultMembers(ctx context.Context, tx *sql.Tx, vaultID string, limit, offset int) ([]*storage.User, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT u.id, u.login, u.public_key, u.created_at, u.updated_at
		FROM users u
		JOIN vault_members vm ON vm.user_id = u.id
		WHERE vm.vault_id = $1
		ORDER BY u.created_at DESC
		LIMIT $2 OFFSET $3
	`, vaultID, limit, offset)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("query vault members: %w", err))
	}
	defer rows.Close()

	var members []*storage.User
	for rows.Next() {
		var member storage.User
		err := rows.Scan(&member.UserID, &member.Login, &member.PublicKey, &member.CreatedAt, &member.UpdatedAt)
		if err != nil {
			return nil, storage.NewInternalError(fmt.Errorf("scan vault member: %w", err))
		}
		members = append(members, &member)
	}

	if err := rows.Err(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("iterate vault members: %w", err))
	}

	return members, nil
}

func (s *PostgresStorage) GetVaultKeyProtected(ctx context.Context, callerID, vaultID string) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})

	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	member, err := s.getVaultMember(ctx, tx, callerID, vaultID)
	if err != nil {
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	vaultKeyProtected, err := s.getVaultKeyProtected(ctx, tx, member.UserID)
	if err != nil {
		return nil, fmt.Errorf("getVaultKeyProtected: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return vaultKeyProtected, nil
}

func (s *PostgresStorage) getVaultKeyProtected(ctx context.Context, tx *sql.Tx, userID string) ([]byte, error) {
	var vaultKeyProtected []byte
	err := tx.QueryRowContext(ctx, `
		SELECT vm.vault_key_protected
		FROM vault_members vm
		WHERE vm.user_id = $1
	`, userID).Scan(&vaultKeyProtected)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("get vault key protected: %w", err))
	}
	return vaultKeyProtected, nil
}

func (s *PostgresStorage) getVaultMember(ctx context.Context, tx *sql.Tx, userID, vaultID string) (*storage.VaultMember, error) {
	var member storage.VaultMember
	err := tx.QueryRowContext(ctx, `
		SELECT vm.user_id, vm.vault_id, vm.created_at
		FROM vault_members vm
		WHERE vm.user_id = $1 AND vm.vault_id = $2
	`, userID, vaultID).Scan(&member.UserID, &member.VaultID, &member.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan vault member with userID %s and vaultID %s: %w", userID, vaultID, err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan vault member: %w", err))
	}
	return &member, nil
}

func (s *PostgresStorage) AddVaultMember(ctx context.Context, callerID, vaultID, userID string, vaultKeyProtected []byte) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return fmt.Errorf("getVaultMember: %w", err)
	}

	exists, err := s.checkVaultAccess(ctx, tx, callerID, vaultID, storage.PermissionVaultManageMembers, time.Now())
	if err != nil {
		return fmt.Errorf("checkVaultAccess: %w", err)
	}
	if !exists {
		return storage.NewNoAccessError(fmt.Errorf("vault access not found: %w", err))
	}

	_, err = s.getVaultMember(ctx, tx, userID, vaultID)
	if err == nil {
		return storage.NewAlreadyExistsError(fmt.Errorf("vault member already exists: %w", err))
	}
	if !storage.IsNotFoundError(err) {
		return fmt.Errorf("getVaultMember: %w", err)
	}

	member := &storage.VaultMember{
		UserID:    userID,
		VaultID:   vaultID,
		CreatedAt: time.Now(),
	}

	if err := s.createVaultMember(ctx, tx, member, vaultKeyProtected); err != nil {
		return fmt.Errorf("createVaultMember: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) createVaultMember(ctx context.Context, tx *sql.Tx, member *storage.VaultMember, vaultKeyProtected []byte) error {
	query := `
		INSERT INTO vault_members (user_id, vault_id, created_at, vault_key_protected)
		VALUES ($1, $2, $3, $4)
	`
	_, err := tx.ExecContext(ctx, query, member.UserID, member.VaultID, member.CreatedAt, vaultKeyProtected)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("insert vault member: %w", err))
	}
	return nil
}

func (s *PostgresStorage) RemoveVaultMember(ctx context.Context, callerID, vaultID, userID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return fmt.Errorf("getVaultMember: %w", err)
	}

	exists, err := s.checkVaultAccess(ctx, tx, callerID, vaultID, storage.PermissionVaultManageMembers, time.Now())
	if err != nil {
		return fmt.Errorf("checkVaultAccess: %w", err)
	}
	if !exists {
		return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
	}

	member, err := s.getVaultMember(ctx, tx, userID, vaultID)
	if err != nil {
		return fmt.Errorf("getVaultMember: %w", err)
	}

	if err := s.deleteVaultMember(ctx, tx, vaultID, member.UserID); err != nil {
		return fmt.Errorf("deleteVaultMember: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) deleteVaultMember(ctx context.Context, tx *sql.Tx, vaultID, userID string) error {
	query := `
		DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2
	`
	_, err := tx.ExecContext(ctx, query, vaultID, userID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("delete vault member: %w", err))
	}
	return nil
}
