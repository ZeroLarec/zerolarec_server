package config

import (
	"fmt"
	"os"

	"github.com/ZeroLarec/zerolarec_server/internal/server"
	"github.com/ZeroLarec/zerolarec_server/internal/storage/postgres"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"db_name"`
	UseTLS   bool   `yaml:"use_tls"`
}

func LoadConfig(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read yaml config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(yamlFile, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal yaml config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) ToServerConfig() server.Config {
	return server.Config{
		Addr: c.Server.Addr,
	}
}

func (c *Config) ToPostgresConfig() postgres.Config {
	return postgres.Config{
		Host:     c.Postgres.Host,
		Port:     c.Postgres.Port,
		User:     c.Postgres.User,
		Password: c.Postgres.Password,
		DBName:   c.Postgres.DBName,
		UseTLS:   c.Postgres.UseTLS,
	}
}
