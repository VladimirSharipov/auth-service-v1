package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/utils"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewAuthService(db *gorm.DB, cfg *config.Config) *AuthService {
	return &AuthService{
		db:  db,
		cfg: cfg,
	}
}

func (s *AuthService) Login(userID, userAgent, ipAddress string) (*models.LoginResponse, error) {
	// Проверяем или создаем пользователя
	var user models.User
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Создаем нового пользователя
			user = models.User{
				ID: uuid.MustParse(userID),
			}
			if err := s.db.Create(&user).Error; err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			return nil, fmt.Errorf("database error: %w", err)
		}
	}

	// Генерируем access токен
	accessToken, accessTokenID, err := utils.GenerateAccessToken(
		userID,
		s.cfg.JWTSecret,
		s.cfg.AccessTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Генерируем refresh токен
	refreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Хешируем refresh токен
	hashedRefreshToken, err := bcrypt.GenerateFromPassword(
		[]byte(utils.HashRefreshToken(refreshToken)),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Сохраняем refresh токен в базу
	refreshTokenModel := models.RefreshToken{
		UserID:        user.ID,
		TokenHash:     string(hashedRefreshToken),
		AccessTokenID: accessTokenID,
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
		ExpiresAt:     time.Now().Add(s.cfg.RefreshTokenDuration),
	}

	if err := s.db.Create(&refreshTokenModel).Error; err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) Refresh(refreshToken, userAgent, ipAddress string) (*models.RefreshResponse, error) {
	hashedToken := utils.HashRefreshToken(refreshToken)

	now := time.Now()

	var tokenModel models.RefreshToken
	if err := s.db.Preload("User").Where("token_hash = ? AND expires_at > ?", hashedToken, now).First(&tokenModel).Error; err != nil {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	// Проверяем хеш токена
	if err := bcrypt.CompareHashAndPassword([]byte(tokenModel.TokenHash), []byte(hashedToken)); err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Проверяем User-Agent
	if tokenModel.UserAgent != userAgent {
		// Деавторизуем пользователя
		s.db.Where("user_id = ?", tokenModel.UserID).Delete(&models.RefreshToken{})
		return nil, fmt.Errorf("user agent mismatch - user deauthorized")
	}

	// Проверяем изменение IP
	if tokenModel.IPAddress != ipAddress {
		// Отправляем webhook
		go s.sendWebhook(tokenModel.UserID.String(), ipAddress, userAgent)
	}

	// Удаляем старый refresh токен (защита от повторного использования)
	if err := s.db.Delete(&tokenModel).Error; err != nil {
		return nil, fmt.Errorf("failed to delete old refresh token: %w", err)
	}

	// Генерируем новые токены
	accessToken, accessTokenID, err := utils.GenerateAccessToken(
		tokenModel.UserID.String(),
		s.cfg.JWTSecret,
		s.cfg.AccessTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Хешируем новый refresh токен
	hashedNewRefreshToken, err := bcrypt.GenerateFromPassword(
		[]byte(utils.HashRefreshToken(newRefreshToken)),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Сохраняем новый refresh токен
	newTokenModel := models.RefreshToken{
		UserID:        tokenModel.UserID,
		TokenHash:     string(hashedNewRefreshToken),
		AccessTokenID: accessTokenID,
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
		ExpiresAt:     now.Add(s.cfg.RefreshTokenDuration),
	}

	if err := s.db.Create(&newTokenModel).Error; err != nil {
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	return &models.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthService) Logout(accessTokenID string) error {
	// Удаляем refresh токен по access token ID
	if err := s.db.Where("access_token_id = ?", accessTokenID).Delete(&models.RefreshToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*utils.JWTClaims, error) {
	return utils.ValidateAccessToken(tokenString, s.cfg.JWTSecret)
}

func (s *AuthService) sendWebhook(userID, ipAddress, userAgent string) {
	payload := models.WebhookPayload{
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload: %v", err)
		return
	}

	resp, err := http.Post(s.cfg.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Failed to send webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Webhook returned non-200 status: %d", resp.StatusCode)
	}
}
