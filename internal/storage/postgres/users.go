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

var _ storage.UserStorage = (*PostgresStorage)(nil)

func (s *PostgresStorage) GetUser(ctx context.Context, userID string) (*storage.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	user, err := s.getUser(ctx, tx, userID)
	if err != nil {
		return nil, fmt.Errorf("getUser: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return user, nil
}

func (s *PostgresStorage) getUser(ctx context.Context, tx *sql.Tx, userID string) (*storage.User, error) {
	query := `
	SELECT id, login, public_key, created_at, updated_at
	FROM users
	WHERE id = $1
	`

	var user storage.User
	err := tx.QueryRowContext(ctx, query, userID).Scan(
		&user.UserID,
		&user.Login,
		&user.PublicKey,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan user: %w", err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan user: %w", err))
	}

	return &user, nil
}

func (s *PostgresStorage) GetUserByLogin(ctx context.Context, login string) (*storage.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	user, err := s.getUserByLogin(ctx, tx, login)
	if err != nil {
		return nil, fmt.Errorf("getUserByLogin: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return user, nil
}

func (s *PostgresStorage) getUserByLogin(ctx context.Context, tx *sql.Tx, login string) (*storage.User, error) {
	var user storage.User
	err := tx.QueryRowContext(ctx, `
	SELECT id, login, public_key, created_at, updated_at
	FROM users
	WHERE login = $1
	`, login).Scan(
		&user.UserID,
		&user.Login,
		&user.PublicKey,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan user: %w", err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan user: %w", err))
	}

	return &user, nil
}

func (s *PostgresStorage) GetUserPasswordHashByLogin(ctx context.Context, login string) ([]byte, error) {
	var passwordHash []byte

	if err := s.db.QueryRowContext(ctx, `
	SELECT password_hash
	FROM users
	WHERE login = $1
	`, login).Scan(&passwordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan user password hash: %w", err))
		}
	}

	return passwordHash, nil

}

func (s *PostgresStorage) GetUserPrivateKeyProtected(ctx context.Context, userID string) ([]byte, error) {
	query := `
	SELECT private_key_protected
	FROM users
	WHERE id = $1
	`

	var privateKeyProtected []byte
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&privateKeyProtected)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.NewNotFoundError(fmt.Errorf("scan private key protected: %w", err))
		}
		return nil, storage.NewInternalError(fmt.Errorf("scan private key protected: %w", err))
	}

	return privateKeyProtected, nil
}
func (s *PostgresStorage) CreateUser(
	ctx context.Context,
	login string,
	publicKey []byte,
	passwordHash []byte,
	privateKeyProtected []byte,
) (*storage.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	_, err = s.getUserByLogin(ctx, tx, login)
	if err == nil {
		return nil, storage.NewAlreadyExistsError(fmt.Errorf("user already exists"))
	} else if !storage.IsNotFoundError(err) {
		return nil, fmt.Errorf("getUserByLogin: %w", err)
	}

	user := &storage.User{
		UserID:    uuid.NewString(),
		Login:     login,
		PublicKey: publicKey,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.createUser(ctx, tx, user, passwordHash, privateKeyProtected); err != nil {
		return nil, fmt.Errorf("createUser: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return user, nil
}

func (s *PostgresStorage) createUser(ctx context.Context, tx *sql.Tx, user *storage.User, passwordHash, privateKeyProtected []byte) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, login, public_key, password_hash, private_key_protected, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		user.UserID,
		user.Login,
		user.PublicKey,
		passwordHash,
		privateKeyProtected,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("execute createUser query: %w", err))
	}
	return nil
}

func (s *PostgresStorage) UpdateUser(ctx context.Context, userID string, login *string) (*storage.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	userToUpdate, err := s.getUser(ctx, tx, userID)
	if err != nil {
		return nil, fmt.Errorf("getUser: %w", err)
	}

	if login != nil {
		userToUpdate.Login = *login
	}

	userToUpdate.UpdatedAt = time.Now()

	if err := s.updateUser(ctx, tx, userToUpdate); err != nil {
		return nil, fmt.Errorf("updateUser: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return userToUpdate, nil
}

func (s *PostgresStorage) updateUser(ctx context.Context, tx *sql.Tx, user *storage.User) error {
	query := `
		UPDATE users
		SET login = $1, updated_at = $2
		WHERE id = $3
	`

	result, err := tx.ExecContext(ctx, query, user.Login, user.UpdatedAt, user.UserID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("execute updateUser query: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("get rows affected: %w", err))
	}
	if rowsAffected == 0 {
		return storage.NewNotFoundError(fmt.Errorf("no rows affected"))
	}

	return nil
}

func (s *PostgresStorage) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("begin transaction: %w", err))
	}
	defer tx.Rollback()

	if err := s.deleteUser(ctx, tx, userID); err != nil {
		return fmt.Errorf("deleteUser: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return storage.NewInternalError(fmt.Errorf("commit transaction: %w", err))
	}

	return nil
}

func (s *PostgresStorage) deleteUser(ctx context.Context, tx *sql.Tx, userID string) error {
	query := `
		DELETE FROM users
		WHERE id = $1
	`

	result, err := tx.ExecContext(ctx, query, userID)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("delete user: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("get rows affected: %w", err))
	}
	if rowsAffected == 0 {
		return storage.NewNotFoundError(fmt.Errorf("no rows affected"))
	}

	return nil
}
