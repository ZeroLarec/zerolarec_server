package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"github.com/google/uuid"
)

var _ storage.SecretStorage = (*PostgresStorage)(nil)

func (s *PostgresStorage) ListSecrets(ctx context.Context, callerID, vaultID string, limit, offset int) ([]*storage.Secret, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	secrets, err := s.listSecrets(ctx, tx, vaultID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listSecrets: %w", err)
	}

	var secretIDs []string
	for _, secret := range secrets {
		secretIDs = append(secretIDs, secret.SecretID)
	}

	isAvailable, err := s.checkSecretsAccess(ctx, tx, callerID, vaultID, secretIDs, storage.PermissionSecretGet, time.Now())
	if err != nil {
		return nil, fmt.Errorf("checkSecretsAccess: %w", err)
	}

	availableSecrets := make([]*storage.Secret, 0)
	for _, secret := range secrets {
		if _, ok := isAvailable[secret.SecretID]; ok {
			availableSecrets = append(availableSecrets, secret)
		}
	}

	return availableSecrets, nil
}

func (s *PostgresStorage) listSecrets(ctx context.Context, tx *sql.Tx, vaultID string, limit, offset int) ([]*storage.Secret, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, vault_id, name, description, key_values, created_at, updated_at
		FROM secrets
		WHERE vault_id = $1
		ORDER BY created_at DESC, id
		LIMIT $2 OFFSET $3
	`, vaultID, limit, offset)
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	defer rows.Close()

	secrets := make([]*storage.Secret, 0)
	for rows.Next() {
		var (
			secret        storage.Secret
			keyValuesJSON []byte
		)
		if err := rows.Scan(&secret.SecretID, &secret.VaultID, &secret.Name, &secret.Description, &keyValuesJSON, &secret.CreatedAt, &secret.UpdatedAt); err != nil {
			return nil, storage.NewInternalError(err)
		}
		keyValues, err := toKeyValuesMap(keyValuesJSON)
		if err != nil {
			return nil, err
		}
		secret.KeyValues = keyValues
		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

func toKeyValuesMap(keyValuesJSON []byte) (map[string][]byte, error) {
	var keyValuesMapBase64 map[string]string
	if err := json.Unmarshal(keyValuesJSON, &keyValuesMapBase64); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("unmarshal key_values JSON: %w", err))
	}

	keyValues := make(map[string][]byte, len(keyValuesMapBase64))
	for k, base64Value := range keyValuesMapBase64 {
		decodedValue, err := base64.StdEncoding.DecodeString(base64Value)
		if err != nil {
			return nil, storage.NewInternalError(fmt.Errorf("decode Base64 value for key %s: %w", k, err))
		}
		keyValues[k] = decodedValue
	}

	return keyValues, nil
}

func (s *PostgresStorage) GetSecret(ctx context.Context, callerID, vaultID, secretID string) (*storage.Secret, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	isAvailable, err := s.checkSecretsAccess(ctx, tx, callerID, vaultID, []string{secretID}, storage.PermissionSecretGet, time.Now())
	if err != nil {
		return nil, fmt.Errorf("checkSecretsAccess: %w", err)
	}
	if _, ok := isAvailable[secretID]; !ok {
		return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
	}

	secret, err := s.getSecret(ctx, tx, secretID)
	if err != nil {
		return nil, fmt.Errorf("getSecret: %w", err)
	}

	return secret, nil
}

func (s *PostgresStorage) getSecret(ctx context.Context, tx *sql.Tx, secretID string) (*storage.Secret, error) {
	var (
		secret        storage.Secret
		keyValuesJSON []byte
	)

	err := tx.QueryRowContext(ctx, `
		SELECT id, vault_id, name, description, key_values, created_at, updated_at
		FROM secrets
		WHERE id = $1
	`, secretID).Scan(&secret.SecretID, &secret.VaultID, &secret.Name, &secret.Description, &keyValuesJSON, &secret.CreatedAt, &secret.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("secret not found: %w", err))
		}
		return nil, storage.NewInternalError(err)
	}

	keyValues, err := toKeyValuesMap(keyValuesJSON)
	if err != nil {
		return nil, err
	}
	secret.KeyValues = keyValues

	return &secret, nil
}

func (s *PostgresStorage) CreateSecret(ctx context.Context, callerID, vaultID, name, description string, keyValues map[string][]byte) (*storage.Secret, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	ok, err := s.checkVaultAccess(ctx, tx, callerID, vaultID, storage.PermissionSecretCreate, time.Now())
	if err != nil {
		return nil, fmt.Errorf("checkVaultAccess: %w", err)
	}
	if !ok {
		return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
	}

	secret := &storage.Secret{
		SecretID:    uuid.NewString(),
		VaultID:     vaultID,
		Name:        name,
		Description: description,
		KeyValues:   keyValues,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.createSecret(ctx, tx, secret); err != nil {
		return nil, fmt.Errorf("createSecret: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return secret, nil
}

func toKeyValuesJSON(keyValues map[string][]byte) ([]byte, error) {
	keyValuesMapBase64 := make(map[string]string, len(keyValues))
	for k, v := range keyValues {
		keyValuesMapBase64[k] = base64.StdEncoding.EncodeToString(v)
	}
	res, err := json.Marshal(keyValuesMapBase64)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("marshal key_values map: %w", err))
	}
	return res, nil
}

func (s *PostgresStorage) createSecret(ctx context.Context, tx *sql.Tx, secret *storage.Secret) error {
	keyValuesJSON, err := toKeyValuesJSON(secret.KeyValues)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO secrets (id, vault_id, name, description, key_values, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, secret.SecretID, secret.VaultID, secret.Name, secret.Description, keyValuesJSON, secret.CreatedAt, secret.UpdatedAt)
	if err != nil {
		return storage.NewInternalError(err)
	}
	return nil
}

func (s *PostgresStorage) UpdateSecret(ctx context.Context, callerID, vaultID, secretID string, name, description *string, keyValues *map[string][]byte) (*storage.Secret, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	defer tx.Rollback()

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return nil, fmt.Errorf("getVaultMember: %w", err)
	}

	secret, err := s.getSecret(ctx, tx, secretID)
	if err != nil {
		return nil, fmt.Errorf("getSecret: %w", err)
	}

	available, err := s.checkSecretsAccess(ctx, tx, callerID, vaultID, []string{secretID}, storage.PermissionSecretUpdate, time.Now())
	if err != nil {
		return nil, fmt.Errorf("checkSecretsAccess: %w", err)
	}
	if _, ok := available[secretID]; !ok {
		return nil, storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
	}

	if name != nil {
		secret.Name = *name
	}
	if description != nil {
		secret.Description = *description
	}
	if keyValues != nil {
		secret.KeyValues = *keyValues
	}
	secret.UpdatedAt = time.Now()

	if err := s.updateSecret(ctx, tx, secret); err != nil {
		return nil, fmt.Errorf("updateSecret: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return secret, nil
}

func (s *PostgresStorage) updateSecret(ctx context.Context, tx *sql.Tx, secret *storage.Secret) error {
	keyValuesJSON, err := toKeyValuesJSON(secret.KeyValues)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE secrets SET name = $1, description = $2, key_values = $3, updated_at = $4 WHERE id = $5
	`, secret.Name, secret.Description, keyValuesJSON, secret.UpdatedAt, secret.SecretID)
	if err != nil {
		return storage.NewInternalError(err)
	}
	return nil
}

func (s *PostgresStorage) DeleteSecret(ctx context.Context, callerID, vaultID, secretID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(err)
	}
	defer tx.Rollback()

	if _, err := s.getSecret(ctx, tx, secretID); err != nil {
		return fmt.Errorf("getSecret: %w", err)
	}

	if _, err := s.getVaultMember(ctx, tx, callerID, vaultID); err != nil {
		if storage.IsNotFoundError(err) {
			return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
		}
		return fmt.Errorf("getVaultMember: %w", err)
	}

	available, err := s.checkSecretsAccess(ctx, tx, callerID, vaultID, []string{secretID}, storage.PermissionSecretDelete, time.Now())
	if err != nil {
		return fmt.Errorf("checkSecretsAccess: %w", err)
	}
	if _, ok := available[secretID]; !ok {
		return storage.NewNoAccessError(fmt.Errorf("vault member not found: %w", err))
	}

	if err := s.deleteSecret(ctx, tx, secretID); err != nil {
		return fmt.Errorf("deleteSecret: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) deleteSecret(ctx context.Context, tx *sql.Tx, secretID string) error {
	res, err := tx.ExecContext(ctx, `
		DELETE FROM secrets WHERE id = $1
	`, secretID)
	if err != nil {
		return storage.NewInternalError(err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return storage.NewInternalError(err)
	}
	if rowsAffected == 0 {
		return storage.NewInternalError(fmt.Errorf("secret not found: %w", err))
	}

	return nil
}
