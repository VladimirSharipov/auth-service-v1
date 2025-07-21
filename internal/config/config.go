package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL          string
	JWTSecret            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	WebhookURL           string
}

func Load() *Config {
	accessTokenDuration, _ := strconv.Atoi(getEnv("ACCESS_TOKEN_DURATION", "900"))      // 15 минут
	refreshTokenDuration, _ := strconv.Atoi(getEnv("REFRESH_TOKEN_DURATION", "604800")) // 7 дней

	return &Config{
		DatabaseURL:          getEnv("DATABASE_URL", "postgres://user:password@localhost/authdb?sslmode=disable"),
		JWTSecret:            getEnv("JWT_SECRET", "your-secret-key"),
		AccessTokenDuration:  time.Duration(accessTokenDuration) * time.Second,
		RefreshTokenDuration: time.Duration(refreshTokenDuration) * time.Second,
		WebhookURL:           getEnv("WEBHOOK_URL", "http://localhost:9000/webhook"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
