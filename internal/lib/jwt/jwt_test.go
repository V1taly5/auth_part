package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAccessToken(t *testing.T) {
	userID := uuid.New()
	ipAddress := "127.0.0.1"
	secretKey := "test-secret"
	expiration := time.Minute
	jwtID := uuid.New().String()

	tokenString, err := GenerateAccessToken(userID, ipAddress, secretKey, expiration, jwtID)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(*AccessTokenClaims)
	assert.True(t, ok)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, jwtID, claims.ID)
}

func TestGenerateRefreshToken(t *testing.T) {
	userID := uuid.New()
	ipAddress := "127.0.0.1"
	secretKey := "test-secret"
	expiration := time.Minute
	accessJwtID := uuid.New().String()
	jwtID := uuid.New().String()

	tokenString, err := GenerateRefreshToken(userID, ipAddress, secretKey, expiration, accessJwtID, jwtID)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(*RefreshTokenClaims)
	assert.True(t, ok)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, jwtID, claims.ID)
	assert.Equal(t, ipAddress, claims.IPAddress)
}

func TestParseToken(t *testing.T) {
	userID := uuid.New()
	ipAddress := "127.0.0.1"
	secretKey := "test-secret"
	expiration := time.Minute
	accessJwtID := uuid.New().String()
	jwtID := uuid.New().String()

	tokenString, err := GenerateRefreshToken(userID, ipAddress, secretKey, expiration, accessJwtID, jwtID)
	assert.NoError(t, err)

	claims, err := ParseToken(tokenString, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, jwtID, claims.ID)
	assert.Equal(t, ipAddress, claims.IPAddress)
}

func TestHashAndVerifyRefreshToken(t *testing.T) {
	refreshToken := "sample-refresh-token"

	hashedToken, err := HashRefreshToken(refreshToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedToken)

	isValid := VerifyRefreshToken(refreshToken, hashedToken)
	assert.True(t, isValid)

	isValid = VerifyRefreshToken("invalid-token", hashedToken)
	assert.False(t, isValid)
}

func TestGenerateJwtID(t *testing.T) {
	jwtID1 := GenerateJwtID()
	jwtID2 := GenerateJwtID()

	assert.NotEmpty(t, jwtID1)
	assert.NotEmpty(t, jwtID2)
	assert.NotEqual(t, jwtID1, jwtID2)
}
