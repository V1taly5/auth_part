package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Server   HTTPServer
	Postgres Postgres
	JWT      JWT
	Email    Email
}

type HTTPServer struct {
	Address     string        `env:"HTTPSERVER_ADDRESS" env-default:"localhost:8080"`
	Timeout     time.Duration `env:"HTTPSERVER_TIMEOUT" env-default:"4s"`
	IdleTimeout time.Duration `env:"HTTPSERVER_IDLE_TIMEOUT" env-default:"60s"`
}

type Postgres struct {
	URL string `env:"POSTGRES_URL" env-required:"true"`
}

type JWT struct {
	AccessSecret      string        `env:"JWT_ACCESS_SECRET" env-required:"true"`
	AccessExpiration  time.Duration `env:"JWT_ACCESS_EXPIRATION" env-default:"15m"`
	RefreshExpiration time.Duration `env:"JWT_REFRESH_EXPIRATION" env-default:"24h"`
}

type Email struct {
	From     string `env:"EMAIL_FROM" env-default:"auth@example.com"`
	Server   string `env:"EMAIL_SERVER" env-default:"smtp.example.com"`
	Port     int    `env:"EMAIL_PORT" env-default:"444"`
	Username string `env:"EMAIL_USERNAME"`
	Password string `env:"EMAIL_PASSWORD"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	err := cleanenv.ReadEnv(cfg)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return nil, err
	}
	return cfg, nil
}
