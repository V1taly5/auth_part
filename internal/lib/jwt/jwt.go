package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

type TokenClaims struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	JwtID     string `json:"jti"` // JWT ID для связи с refresh token
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID uuid.UUID, ipAdress string, secretKey string, expiration time.Duration, jwtID string) (string, error) {
	now := time.Now()

	accessClaim := TokenClaims{
		UserID:    userID.String(),
		IPAddress: ipAdress,
		JwtID:     jwtID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jwtID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaim)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func GenerateRefreshToken(userID uuid.UUID, ipAdress string, secretKey string, expiration time.Duration, jwtID string) (string, error) {
	now := time.Now()

	refreshClime := TokenClaims{
		UserID:    userID.String(),
		IPAddress: ipAdress,
		JwtID:     jwtID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jwtID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClime)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ParseToken(tokenString, secretKey string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != "HS512" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

func HashRefreshToken(refreshToken string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyRefreshToken(refreshToken, hashRefreshToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashRefreshToken), []byte(refreshToken))
	return err == nil
}

func GenerateJwtID() string {
	return uuid.New().String()
}
