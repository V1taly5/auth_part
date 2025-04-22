package services

import (
	"context"
	"pas/internal/config"
	"pas/internal/lib/jwt"
	"pas/internal/lib/mail"
	mockstorage "pas/internal/mock/mock_storage"
	"pas/internal/models"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGenerateTokens_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mockstorage.NewMockIstorage(ctrl)
	mockMailSender := &mail.MockEmailSender{} // Предположим, у вас есть мок для mail.Sender

	cfg := &config.Config{
		JWT: config.JWT{
			AccessSecret:      "access-secret",
			AccessExpiration:  15 * time.Minute,
			RefreshExpiration: 7 * 24 * time.Hour,
		},
	}

	authService := New(mockStorage, mockMailSender, cfg)

	userID := uuid.New()
	ipAddress := "127.0.0.1"

	mockStorage.EXPECT().GetUserByID(gomock.Any(), userID).Return(&models.User{ID: userID}, nil)
	mockStorage.EXPECT().CreateRefreshToken(gomock.Any(), gomock.Any()).Return(nil)

	tokens, err := authService.GenerateTokens(context.Background(), userID, ipAddress)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestRefreshTokens_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mockstorage.NewMockIstorage(ctrl)
	mockMailSender := &mail.MockEmailSender{}
	cfg := &config.Config{
		JWT: config.JWT{
			AccessSecret:      "my-access-secret-key",
			AccessExpiration:  15 * time.Minute,
			RefreshExpiration: 24 * time.Hour,
		},
	}

	authService := New(mockStorage, mockMailSender, cfg)

	userID := uuid.New()
	jwtID := uuid.MustParse("6d1f58c4-2b0d-4600-9a0a-c1b74389af6d")
	ipAddress := "127.0.0.1"
	oldRefreshToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpcF9hZGRyZXNzIjoiMTcyLjE5LjAuMSIsImlzcyI6IjEyM2U0NTY3LWU4OWItMTJkMy1hNDU2LTQyNjYxNDE3NDAwMCIsInN1YiI6IjEyM2U0NTY3LWU4OWItMTJkMy1hNDU2LTQyNjYxNDE3NDAwMCIsImV4cCI6MTc0NTQxNDAyOSwibmJmIjoxNzQ1MzI3NjI5LCJpYXQiOjE3NDUzMjc2MjksImp0aSI6IjZkMWY1OGM0LTJiMGQtNDYwMC05YTBhLWMxYjc0Mzg5YWY2ZCJ9.gvcPGkwJVNQ_UO1yAOnp0wwprxNB8CfVpQg7r2r2mYbpwAOaM_U7_btoxNP8SZSVpYMxJYuXIi7IpkAgUeK2eA"

	hashToken, err := jwt.HashRefreshToken(oldRefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, hashToken)

	tokenData := &models.RefreshTokenData{
		ID:        jwtID,
		UserID:    userID,
		TokenHash: hashToken,
		IPAddress: ipAddress,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		JWTID:     uuid.New().String(),
	}

	mockStorage.EXPECT().GetRefreshTokenById(gomock.Any(), jwtID).Return(tokenData, nil)
	mockStorage.EXPECT().CreateAndRevokeRefreshToken(gomock.Any(), gomock.Any(), jwtID).Return(nil)

	tokens, err := authService.RefreshTokens(context.Background(), oldRefreshToken, ipAddress)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestHandleIPAddressChange_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mockstorage.NewMockIstorage(ctrl)
	mockMailSender := &mail.MockEmailSender{}
	cfg := &config.Config{}

	authService := New(mockStorage, mockMailSender, cfg)

	userID := uuid.New()
	oldIP := "192.168.1.1"
	newIP := "10.0.0.1"
	userEmail := "auth@mail.com"

	mockStorage.EXPECT().GetUserByID(gomock.Any(), userID).Return(&models.User{ID: userID, Email: userEmail}, nil)
	err := mockMailSender.SendIPChangeWarning(userEmail, oldIP, newIP)
	assert.NoError(t, err)
	assert.True(t, mockMailSender.Called)

	err = authService.handleIPAddressChange(context.Background(), userID, oldIP, newIP)
	assert.NoError(t, err)
}
