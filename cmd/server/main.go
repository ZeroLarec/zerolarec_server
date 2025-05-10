package main

import (
	"context"
	"flag"
	"log"

	"github.com/ZeroLarec/zerolarec_server/internal/config"
	"github.com/ZeroLarec/zerolarec_server/internal/server"
	"github.com/ZeroLarec/zerolarec_server/internal/storage/postgres"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfgPath = flag.String("config", "", "path to config file")
	flag.Parse()
	if *cfgPath == "" {
		log.Fatalf("config file path is required")
	}

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	pgStorage, err := postgres.NewStorage(ctx, cfg.ToPostgresConfig())
	if err != nil {
		log.Fatalf("failed to create postgres storage: %v", err)
	}

	s, err := server.NewServer(cfg.ToServerConfig(), pgStorage)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	log.Println("starting server...")

	if err := s.Run(); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
