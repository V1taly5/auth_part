package jwt

import (
	"crypto/sha256"
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

type RefreshTokenClaims struct {
	IPAddress string `json:"ip_address"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID uuid.UUID, ipAdress string, secretKey string, expiration time.Duration, jwtID string) (string, error) {
	now := time.Now()

	accessClaim := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
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

func GenerateRefreshToken(
	userID uuid.UUID,
	ipAdress string,
	secretKey string,
	expiration time.Duration,
	accessJwtID string,
	JwtID string,
) (
	string,
	error,
) {
	now := time.Now()
	refreshClime := RefreshTokenClaims{
		IPAddress: ipAdress,
		// AccessJwtID: accessJwtID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        JwtID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClime)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ParseToken(tokenString, secretKey string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
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

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

func HashRefreshToken(refreshToken string) (string, error) {
	// limiting the size of the input data
	sha256Hash := sha256.Sum256([]byte(refreshToken))
	hash, err := bcrypt.GenerateFromPassword(sha256Hash[:], bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyRefreshToken(refreshToken, hashRefreshToken string) bool {
	sha256Hash := sha256.Sum256([]byte(refreshToken))
	err := bcrypt.CompareHashAndPassword([]byte(hashRefreshToken), sha256Hash[:])
	return err == nil
}

func GenerateJwtID() string {
	return uuid.New().String()
}
