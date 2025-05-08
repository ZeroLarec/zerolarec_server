package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var _ storage.AccessRuleStorage = (*PostgresStorage)(nil)

func (s *PostgresStorage) checkVaultAccess(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	vaultID string,
	permission storage.Permission,
	timestamp time.Time,
) (bool, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM access_rules ar
			WHERE ar.user_id = $1
			AND ar.vault_id = $2
			AND ar.secret_id IS NULL
			AND $3 = ANY(ar.permissions)
			AND (ar.expires_at IS NULL OR ar.expires_at > $4)
		)`, userID, vaultID, permission, timestamp,
	).Scan(&exists); err != nil {
		return false, storage.NewInternalError(fmt.Errorf("check permission: %w", err))
	}

	return exists, nil
}

func (s *PostgresStorage) checkSecretsAccess(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	vaultID string,
	secretIDs []string,
	permission storage.Permission,
	timestamp time.Time,
) (available map[string]struct{}, err error) {
	available = make(map[string]struct{}, len(secretIDs))

	exists, err := s.checkVaultAccess(ctx, tx, userID, vaultID, permission, timestamp)
	if err != nil {
		return nil, fmt.Errorf("checkVaultAccess: %w", err)
	}
	if exists {
		for _, secretID := range secretIDs {
			available[secretID] = struct{}{}
		}
		return available, nil
	}

	rows, err := tx.QueryContext(ctx, `
	WITH required_secrets AS (
		SELECT unnest($1::varchar[]) AS secret_id
	)

	SELECT rs.secret_id
	FROM required_secrets rs
	JOIN access_rules ar ON ar.secret_id = rs.secret_id
	WHERE ar.user_id = $2
	AND $3 = ANY(ar.permissions)
	AND (ar.expires_at IS NULL OR ar.expires_at > $4)
	`, pq.Array(secretIDs), userID, permission, timestamp)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("query access rules: %w", err))
	}
	defer rows.Close()

	for rows.Next() {
		var secretID string
		if err := rows.Scan(&secretID); err != nil {
			return nil, storage.NewInternalError(fmt.Errorf("scan secret ID: %w", err))
		}
		available[secretID] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("iterate access rules: %w", err))
	}

	return available, nil
}

func (s *PostgresStorage) ListAccessRules(ctx context.Context, callerID, vaultID string, limit, offset int) ([]*storage.AccessRule, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVault(ctx, tx, vaultID); err != nil {
		return nil, fmt.Errorf("getVault: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	accessRules, err := s.listAccessRules(ctx, tx, vaultID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listAccessRules: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return accessRules, nil
}
func (s *PostgresStorage) listAccessRules(ctx context.Context, tx *sql.Tx, vaultID string, limit, offset int) ([]*storage.AccessRule, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, user_id, vault_id, secret_id, description, permissions, expires_at, created_at, updated_at
		FROM access_rules
		WHERE vault_id = $1
		LIMIT $2 OFFSET $3
	`, vaultID, limit, offset)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("query access rules: %w", err))
	}
	defer rows.Close()

	var accessRules []*storage.AccessRule
	for rows.Next() {
		var (
			accessRule  storage.AccessRule
			permissions []string
			secretID    sql.NullString
		)
		err := rows.Scan(
			&accessRule.AccessRuleID,
			&accessRule.UserID,
			&accessRule.VaultID,
			&secretID,
			&accessRule.Description,
			pq.Array(&permissions),
			&accessRule.ExpiresAt,
			&accessRule.CreatedAt,
			&accessRule.UpdatedAt,
		)
		if err != nil {
			return nil, storage.NewInternalError(fmt.Errorf("scan access rule: %w", err))
		}
		accessRule.Permissions = make([]storage.Permission, len(permissions))
		for i, p := range permissions {
			accessRule.Permissions[i] = storage.Permission(p)
		}
		if secretID.Valid {
			accessRule.SecretID = secretID.String
		}
		accessRules = append(accessRules, &accessRule)
	}

	if err := rows.Err(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("iterate access rules: %w", err))
	}

	return accessRules, nil
}

func (s *PostgresStorage) GetAccessRule(ctx context.Context, callerID, accessRuleID string) (*storage.AccessRule, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	accessRule, err := s.getAccessRule(ctx, tx, accessRuleID)
	if err != nil {
		return nil, fmt.Errorf("getAccessRule: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, accessRule.VaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return accessRule, nil
}

func (s *PostgresStorage) getAccessRule(ctx context.Context, tx *sql.Tx, accessRuleID string) (*storage.AccessRule, error) {
	var (
		accessRule  storage.AccessRule
		permissions []string
		secretID    sql.NullString
	)
	err := tx.QueryRowContext(ctx, `
		SELECT id, user_id, vault_id, secret_id, description, permissions, expires_at, created_at, updated_at
		FROM access_rules
		WHERE id = $1
	`, accessRuleID).Scan(
		&accessRule.AccessRuleID,
		&accessRule.UserID,
		&accessRule.VaultID,
		&secretID,
		&accessRule.Description,
		pq.Array(&permissions),
		&accessRule.ExpiresAt,
		&accessRule.CreatedAt,
		&accessRule.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan access rule: %w", err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan access rule: %w", err))
	}

	if secretID.Valid {
		accessRule.SecretID = secretID.String
	}

	accessRule.Permissions = make([]storage.Permission, len(permissions))
	for i, p := range permissions {
		accessRule.Permissions[i] = storage.Permission(p)
	}

	return &accessRule, nil
}

func (s *PostgresStorage) CreateAccessRule(
	ctx context.Context,
	callerID string,
	userID string,
	vaultID string,
	secretID string,
	description string,
	permissions []storage.Permission,
	expiresAt time.Time,
) (*storage.AccessRule, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if _, err := s.getVault(ctx, tx, vaultID); err != nil {
		return nil, fmt.Errorf("getVault: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	if secretID == "" {
		haveAccess, err := s.checkVaultAccess(ctx, tx, callerID, vaultID, storage.PermissionVaultGrantAccess, time.Now())
		if err != nil {
			return nil, fmt.Errorf("checkVaultAccess: %w", err)
		}
		if !haveAccess {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
	} else {
		available, err := s.checkSecretsAccess(ctx, tx, callerID, vaultID, []string{secretID}, storage.PermissionSecretGrantAccess, time.Now())
		if err != nil {
			return nil, fmt.Errorf("checkSecretsAccess: %w", err)
		}
		if _, ok := available[secretID]; !ok {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
	}

	if _, err := s.getVaultMember(ctx, tx, userID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewBadRequestError(fmt.Errorf("user is not a member of the vault"))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	accessRule := &storage.AccessRule{
		AccessRuleID: uuid.NewString(),
		UserID:       userID,
		VaultID:      vaultID,
		SecretID:     secretID,
		Description:  description,
		Permissions:  permissions,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.createAccessRule(ctx, tx, accessRule); err != nil {
		return nil, fmt.Errorf("createAccessRule: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return accessRule, nil
}

func (s *PostgresStorage) createAccessRule(ctx context.Context, tx *sql.Tx, accessRule *storage.AccessRule) error {
	queryWithSecret := `
		INSERT INTO access_rules (id, user_id, vault_id, secret_id, description, permissions, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	queryWithoutSecret := `
		INSERT INTO access_rules (id, user_id, vault_id, description, permissions, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	permissionsStr := make([]string, len(accessRule.Permissions))
	for i, p := range accessRule.Permissions {
		permissionsStr[i] = string(p)
	}

	var err error
	if accessRule.SecretID != "" {
		_, err = tx.ExecContext(ctx, queryWithSecret,
			accessRule.AccessRuleID,
			accessRule.UserID,
			accessRule.VaultID,
			accessRule.SecretID,
			accessRule.Description,
			pq.Array(permissionsStr),
			accessRule.ExpiresAt,
			accessRule.CreatedAt,
			accessRule.UpdatedAt,
		)
	} else {
		_, err = tx.ExecContext(ctx, queryWithoutSecret,
			accessRule.AccessRuleID,
			accessRule.UserID,
			accessRule.VaultID,
			accessRule.Description,
			pq.Array(permissionsStr),
			accessRule.ExpiresAt,
			accessRule.CreatedAt,
			accessRule.UpdatedAt,
		)
	}
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("insert access rule: %w", err))
	}
	return nil
}

func (s *PostgresStorage) UpdateAccessRule(
	ctx context.Context,
	callerID string,
	accessRuleID string,
	description *string,
	permissions *[]storage.Permission,
	expiresAt *time.Time,
) (*storage.AccessRule, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	accessRule, err := s.getAccessRule(ctx, tx, accessRuleID)
	if err != nil {
		return nil, fmt.Errorf("getAccessRule: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, accessRule.VaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	if accessRule.SecretID == "" {
		haveAccess, err := s.checkVaultAccess(ctx, tx, callerID, accessRule.VaultID, storage.PermissionVaultGrantAccess, time.Now())
		if err != nil {
			return nil, fmt.Errorf("checkVaultAccess: %w", err)
		}
		if !haveAccess {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
	} else {
		available, err := s.checkSecretsAccess(ctx, tx, callerID, accessRule.VaultID, []string{accessRule.SecretID}, storage.PermissionSecretGrantAccess, time.Now())
		if err != nil {
			return nil, fmt.Errorf("checkSecretsAccess: %w", err)
		}
		if _, ok := available[accessRule.SecretID]; !ok {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
	}

	if description != nil {
		accessRule.Description = *description
	}
	if permissions != nil {
		accessRule.Permissions = *permissions
	}
	if expiresAt != nil {
		accessRule.ExpiresAt = *expiresAt
	}
	accessRule.UpdatedAt = time.Now()

	if err := s.updateAccessRule(ctx, tx, accessRule); err != nil {
		return nil, fmt.Errorf("updateAccessRule: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return accessRule, nil
}

func (s *PostgresStorage) updateAccessRule(ctx context.Context, tx *sql.Tx, accessRule *storage.AccessRule) error {
	query := `
		UPDATE access_rules
		SET description = $1, permissions = $2, expires_at = $3, updated_at = $4
		WHERE id = $5
	`
	permissionsStr := make([]string, len(accessRule.Permissions))
	for i, p := range accessRule.Permissions {
		permissionsStr[i] = string(p)
	}
	_, err := tx.ExecContext(ctx, query, accessRule.Description, pq.Array(permissionsStr), accessRule.ExpiresAt, accessRule.UpdatedAt, accessRule.AccessRuleID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("update access rule: %w", err))
	}
	return nil
}

func (s *PostgresStorage) DeleteAccessRule(ctx context.Context, callerID, accessRuleID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	accessRule, err := s.getAccessRule(ctx, tx, accessRuleID)
	if err != nil {
		return fmt.Errorf("getAccessRule: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, accessRule.VaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return fmt.Errorf("getVaultMember: %w", err)
	}

	if accessRule.SecretID == "" {
		haveAccess, err := s.checkVaultAccess(ctx, tx, callerID, accessRule.VaultID, storage.PermissionVaultGrantAccess, time.Now())
		if err != nil {
			return fmt.Errorf("checkVaultAccess: %w", err)
		}
		if !haveAccess {
			return storage.NewNoAccessError(fmt.Errorf("vault access not found: %w", err))
		}
	} else {
		available, err := s.checkSecretsAccess(ctx, tx, callerID, accessRule.VaultID, []string{accessRule.SecretID}, storage.PermissionSecretGrantAccess, time.Now())
		if err != nil {
			return fmt.Errorf("checkSecretsAccess: %w", err)
		}
		if _, ok := available[accessRule.SecretID]; !ok {
			return storage.NewNoAccessError(fmt.Errorf("vault access not found: %w", err))
		}
	}

	if err := s.deleteAccessRule(ctx, tx, accessRuleID); err != nil {
		return fmt.Errorf("deleteAccessRule: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) deleteAccessRule(ctx context.Context, tx *sql.Tx, accessRuleID string) error {
	_, err := tx.ExecContext(ctx, `
		DELETE FROM access_rules WHERE id = $1
	`, accessRuleID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("delete access rule: %w", err))
	}
	return nil
}
