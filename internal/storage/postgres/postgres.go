package postgres

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Config struct {
	Host     string
	Port     uint16
	User     string
	Password string
	DBName   string
	UseTLS   bool
}

type PostgresStorage struct {
	cfg Config
	db  *sql.DB
}

func NewStorage(ctx context.Context, config Config) (*PostgresStorage, error) {
	var sslMode string
	if config.UseTLS {
		sslMode = "require"
	} else {
		sslMode = "disable"
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		config.User, config.Password, config.Host, config.Port, config.DBName, sslMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &PostgresStorage{
		cfg: config,
		db:  db,
	}, nil
}
