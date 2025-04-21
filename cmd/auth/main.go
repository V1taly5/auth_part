package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"pas/internal/config"
	httpserver "pas/internal/http-server"
	"pas/internal/lib/logger/sl"
	"pas/internal/lib/mail"
	"pas/internal/services"
	"pas/internal/storage/psql"
	"syscall"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load env: %v", err)
	}

	var cfg config.Config

	err = cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatalf("Failed to read env: %v", err)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	connConfig, err := pgx.ParseConfig(cfg.Postgres.URL)
	if err != nil {
		log.Error("Failed to parse postgres URL", sl.Err(err))
	}

	db := sqlx.NewDb(stdlib.OpenDB(*connConfig), "pgx")
	if err := db.Ping(); err != nil {
		log.Error("Failed to connect to database", sl.Err(err))
	}
	defer db.Close()

	storage := psql.New(db)

	mailSender := mail.NewMockEmailSender()

	authService := services.New(storage, mailSender, &cfg)

	router := httpserver.SetupRoutes(log, authService)

	log.Info("starting server", slog.String("address", cfg.Server.Address))

	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  cfg.Server.Timeout,
		WriteTimeout: cfg.Server.Timeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		log.Info("Starting server")
		if err := srv.ListenAndServe(); err != nil {
			log.Error("Failed to start server", sl.Err(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", sl.Err(err))
	}

	log.Info("Server exiting")
}
