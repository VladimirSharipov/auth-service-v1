package handlers

import (
	"net/http"

	"auth-service/internal/models"
	"auth-service/internal/services"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Login получает пару токенов для пользователя
// @Summary Получение пары токенов
// @Description Получить access и refresh токены для пользователя по его GUID
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "User ID"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	response, err := h.authService.Login(req.UserID, userAgent, ipAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Refresh обновляет пару токенов
// @Summary Обновление пары токенов
// @Description Обновить access и refresh токены используя refresh токен
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RefreshRequest true "Refresh Token"
// @Success 200 {object} models.RefreshResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req models.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	response, err := h.authService.Refresh(req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Logout деавторизует пользователя
// @Summary Деавторизация пользователя
// @Description Деавторизует пользователя, инвалидируя refresh токен
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	accessTokenID := c.GetString("access_token_id")

	err := h.authService.Logout(accessTokenID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "successfully logged out"})
}

// GetMe получает GUID текущего пользователя
// @Summary Получение GUID текущего пользователя
// @Description Получить GUID пользователя из токена авторизации
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.MeResponse
// @Failure 401 {object} models.ErrorResponse
// @Router /auth/me [get]
func (h *AuthHandler) GetMe(c *gin.Context) {
	userID := c.GetString("user_id")

	c.JSON(http.StatusOK, models.MeResponse{
		UserID: userID,
	})
}
