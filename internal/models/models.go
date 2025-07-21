package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

type RefreshToken struct {
	ID            uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID        uuid.UUID      `json:"user_id" gorm:"type:uuid;not null"`
	TokenHash     string         `json:"-" gorm:"not null;uniqueIndex:idx_token_hash"`
	AccessTokenID string         `json:"access_token_id" gorm:"not null"`
	UserAgent     string         `json:"user_agent" gorm:"not null"`
	IPAddress     string         `json:"ip_address" gorm:"not null"`
	ExpiresAt     time.Time      `json:"expires_at" gorm:"not null"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `json:"-" gorm:"index"`

	User User `json:"user" gorm:"foreignKey:UserID"`
}

type LoginRequest struct {
	UserID string `json:"user_id" binding:"required" example:"123e4567-e89b-12d3-a456-426614174000"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"dGVzdC1yZWZyZXNoLXRva2Vu"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"dGVzdC1yZWZyZXNoLXRva2Vu"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"dGVzdC1yZWZyZXNoLXRva2Vu"`
}

type MeResponse struct {
	UserID string `json:"user_id" example:"123e4567-e89b-12d3-a456-426614174000"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"invalid credentials"`
}

type WebhookPayload struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Timestamp string `json:"timestamp"`
}
