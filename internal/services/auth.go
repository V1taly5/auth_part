package services

import (
	"context"
	"errors"
	"pas/internal/config"
	"pas/internal/lib/jwt"
	"pas/internal/lib/mail"
	"pas/internal/models"
	"pas/internal/storage/psql"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrUserNotFound     = errors.New("user not found")
	ErrTokenNotFound    = errors.New("token not found")
	ErrExpiredToken     = errors.New("token expired")
	ErrTokenAlreadyUsed = errors.New("token has already been used")
)

type Iauth interface {
}

type Auth struct {
	storage    psql.Istorage
	mailSender mail.Sender
	config     *config.Config
}

func New(storage psql.Istorage, mailSender mail.Sender, config *config.Config) *Auth {
	return &Auth{
		storage:    storage,
		mailSender: mailSender,
		config:     config,
	}
}

func (a *Auth) GenerateTokens(ctx context.Context, userID uuid.UUID, ipAddress string) (*models.TokenPairs, error) {

	_, err := a.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	jwtID := jwt.GenerateJwtID()

	accessToken, err := jwt.GenerateAccessToken(
		userID, ipAddress, a.config.JWT.AccessSecret, a.config.JWT.AccessExpiration, jwtID,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := jwt.GenerateRefreshToken(
		userID, ipAddress, a.config.JWT.AccessSecret, a.config.JWT.RefreshExpiration, jwtID,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	hashRefreshToken, err := jwt.HashRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	refreshTokenData := &models.RefreshTokenData{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hashRefreshToken,
		IPAddress: ipAddress,
		ExpiresAt: now.Add(a.config.JWT.RefreshExpiration),
		CreatedAt: now,
		Revoked:   false,
		JWTID:     jwtID,
	}

	err = a.storage.CreateRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return nil, err
	}

	return &models.TokenPairs{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil

}

func (a *Auth) RefreshTokens(ctx context.Context, refreshToken string, ipAddress string) (*models.TokenPairs, error) {
	claims, err := jwt.ParseToken(refreshToken, a.config.JWT.AccessSecret)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, err
	}
	jwtID, err := uuid.Parse(claims.JwtID)
	if err != nil {
		return nil, err
	}

	refreshTokenData, err := a.storage.GetRefreshToken(ctx, userID, jwtID)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	if !jwt.VerifyRefreshToken(refreshToken, refreshTokenData.TokenHash) {
		return nil, ErrInvalidToken
	}

	if time.Now().After(refreshTokenData.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	if refreshTokenData.Revoked {
		return nil, ErrTokenAlreadyUsed
	}

	if refreshTokenData.IPAddress != ipAddress {
		user, err := a.storage.GetUserByID(ctx, userID)
		if err != nil {
			return nil, ErrUserNotFound
		}

		if err := a.mailSender.SendIPChangeWarning(user.Email, refreshTokenData.IPAddress, ipAddress); err != nil {
			// log error
			// continue

		}
	}

	if err := a.storage.RevokeRefreshToken(ctx, jwtID); err != nil {
		return nil, err
	}
	return a.GenerateTokens(ctx, userID, ipAddress)
}
