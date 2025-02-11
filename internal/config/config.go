package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	JWTSecret          string
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	SMTPHost           string
	SMTPPort           int
	SMTPUser           string
	SMTPPassword       string
}

func GetConfig() *Config {
	if err := godotenv.Load(); err != nil {
		panic("Failed to load environment variables")
	}

	return &Config{
		JWTSecret:          os.Getenv("JWT_SECRET"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		SMTPHost:           os.Getenv("SMTP_HOST"),
		SMTPPort:           getIntEnv("SMTP_PORT", 587),
		SMTPUser:           os.Getenv("SMTP_USER"),
		SMTPPassword:       os.Getenv("SMTP_PASSWORD"),
	}
}

func getIntEnv(key string, defaultVal int) int {
	val, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return defaultVal
	}
	return val
}
