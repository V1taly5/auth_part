package services

import (
	"context"
	"errors"
	"fmt"
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

	tokenPairsData, err := a.createTokenPair(userID, ipAddress)
	if err != nil {
		return nil, err
	}

	err = a.storeRefreshToken(
		ctx, tokenPairsData.RefreshToken, tokenPairsData.RefreshJwtID, userID, ipAddress, tokenPairsData.AccessJwtID,
	)
	if err != nil {
		return nil, err
	}
	return &models.TokenPairs{
		AccessToken:  tokenPairsData.AccessToken,
		RefreshToken: tokenPairsData.RefreshToken,
	}, nil
}

func (a *Auth) RefreshTokens(ctx context.Context, oldRefreshToken string, ipAddress string) (*models.TokenPairs, error) {
	claims, err := jwt.ParseToken(oldRefreshToken, a.config.JWT.AccessSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	jwtID, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh jwt uuid")
	}
	existingTokenData, err := a.storage.GetRefreshTokenById(ctx, jwtID)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	if err := validateRefreshToken(oldRefreshToken, existingTokenData, ipAddress); err != nil {
		return nil, err
	}

	if existingTokenData.IPAddress != ipAddress {
		if err := a.handleIPAddressChange(
			ctx, existingTokenData.UserID, existingTokenData.IPAddress, ipAddress,
		); err != nil {
			// log err
		}
	}

	tokenPairs, err := a.generateNewTokenPair(existingTokenData, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new pair token: %w", err)
	}

	if err := a.rotateRefreshToken(ctx, tokenPairs.RefreshToken, existingTokenData); err != nil {
		return nil, fmt.Errorf("failed to save new token: %w", err)
	}
	return tokenPairs, nil
}

func validateRefreshToken(token string, tokenData *models.RefreshTokenData, ipAddress string) error {
	if !jwt.VerifyRefreshToken(token, tokenData.TokenHash) {
		return ErrInvalidToken
	}
	if time.Now().After(tokenData.ExpiresAt) {
		return ErrExpiredToken
	}
	if tokenData.Revoked {
		return ErrTokenAlreadyUsed
	}
	return nil
}

func (a *Auth) handleIPAddressChange(ctx context.Context, userID uuid.UUID, oldIP, newIP string) error {
	user, err := a.storage.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}
	return a.mailSender.SendIPChangeWarning(user.Email, oldIP, newIP)
}

type TokenPairsData struct {
	AccessToken  string
	RefreshToken string
	AccessJwtID  string
	RefreshJwtID string
}

func (a *Auth) createTokenPair(userID uuid.UUID, ipAddress string) (*TokenPairsData, error) {
	accessJwtID := jwt.GenerateJwtID()

	accessToken, err := jwt.GenerateAccessToken(
		userID, ipAddress, a.config.JWT.AccessSecret, a.config.JWT.AccessExpiration, accessJwtID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshJwtID := jwt.GenerateJwtID()
	refreshToken, err := jwt.GenerateRefreshToken(
		userID,
		ipAddress,
		a.config.JWT.AccessSecret,
		a.config.JWT.RefreshExpiration,
		accessJwtID,
		refreshJwtID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPairsData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessJwtID:  accessJwtID,
		RefreshJwtID: refreshJwtID,
	}, nil
}

func (a *Auth) storeRefreshToken(
	ctx context.Context, refreshToken string, refreshJwtID string, userID uuid.UUID, ipAddress string, accessJwtID string,
) error {
	hashRefreshToken, err := jwt.HashRefreshToken(refreshToken)
	if err != nil {
		return fmt.Errorf("failed to hash refresh token: %w", err)
	}

	refreshID, err := uuid.Parse(refreshJwtID)
	if err != nil {
		return fmt.Errorf("failed to parse refresh jwt uuid: %w", err)
	}

	now := time.Now()
	refreshTokenData := &models.RefreshTokenData{
		ID:        refreshID,
		UserID:    userID,
		TokenHash: hashRefreshToken,
		IPAddress: ipAddress,
		ExpiresAt: now.Add(a.config.JWT.RefreshExpiration),
		CreatedAt: now,
		Revoked:   false,
		JWTID:     accessJwtID,
	}

	err = a.storage.CreateRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	return nil
}

func (a *Auth) generateNewTokenPair(existingToken *models.RefreshTokenData, ipAddress string) (*models.TokenPairs, error) {
	newAccessJwtID := jwt.GenerateJwtID()
	accessToken, err := jwt.GenerateAccessToken(
		existingToken.UserID,
		ipAddress,
		a.config.JWT.AccessSecret,
		a.config.JWT.AccessExpiration,
		newAccessJwtID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshJwtID := jwt.GenerateJwtID()
	refreshToken, err := jwt.GenerateRefreshToken(
		existingToken.UserID,
		ipAddress,
		a.config.JWT.AccessSecret,
		a.config.JWT.AccessExpiration,
		newAccessJwtID,
		newRefreshJwtID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &models.TokenPairs{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *Auth) rotateRefreshToken(
	ctx context.Context, refreshToken string, existingToken *models.RefreshTokenData,
) error {
	hashedToken, err := jwt.HashRefreshToken(refreshToken)
	if err != nil {
		return fmt.Errorf("failed to hash refresh token: %w", err)
	}

	newRefreshJwtID := jwt.GenerateJwtID()
	newRefreshID, err := uuid.Parse(newRefreshJwtID)
	if err != nil {
		return fmt.Errorf("failed to parse new JWT uuid: %w", err)
	}

	now := time.Now()
	newToken := &models.RefreshTokenData{
		ID:        newRefreshID,
		UserID:    existingToken.UserID,
		TokenHash: hashedToken,
		IPAddress: existingToken.IPAddress,
		ExpiresAt: now.Add(a.config.JWT.AccessExpiration),
		CreatedAt: now,
		Revoked:   false,
		JWTID:     existingToken.JWTID,
	}

	if err := a.storage.CreateRefreshToken(ctx, newToken); err != nil {
		return fmt.Errorf("failed to save new refresh token: %w", err)
	}

	if err := a.storage.RevokeRefreshToken(ctx, existingToken.ID); err != nil {
		return fmt.Errorf("failed to revok old refresh token: %w", err)
	}

	return nil
}
