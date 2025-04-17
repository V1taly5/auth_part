package models

import (
	"time"

	"github.com/google/uuid"
)

type TokenPairs struct {
	AccessToken  string `json:"access_tocken"`
	RefreshToken string `json:"refresh_tocker"`
}

type RefreshTokenData struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	IPAddress string    `db:"ip_address"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
	Revoked   bool      `db:"revoked"`
	JWTID     string    `db:"jwt_id"`
}

type User struct {
	ID    uuid.UUID `db:"id"`
	Email string    `db:"email"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}
