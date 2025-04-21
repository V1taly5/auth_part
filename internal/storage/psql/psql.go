package psql

import (
	"context"
	"pas/internal/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type Storage struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Storage {
	return &Storage{db: db}
}

func (s *Storage) CreateRefreshToken(ctx context.Context, tokenData *models.RefreshTokenData) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.db.ExecContext(
		ctx,
		query,
		tokenData.ID,
		tokenData.UserID,
		tokenData.TokenHash,
		tokenData.IPAddress,
		tokenData.ExpiresAt,
		tokenData.CreatedAt,
		tokenData.Revoked,
		tokenData.JWTID,
	)

	return err
}

func (s *Storage) GetRefreshToken(ctx context.Context, userID uuid.UUID, jwtID uuid.UUID) (*models.RefreshTokenData, error) {
	var refreshTokenData models.RefreshTokenData

	query := `
		SELECT id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id
		FROM refresh_tokens
		WHERE user_id = $1 AND jwt_id = $2 AND revoked = false 
	`
	err := s.db.GetContext(ctx, &refreshTokenData, query, userID.String(), jwtID.String())
	if err != nil {
		return nil, err
	}

	return &refreshTokenData, nil
}

func (s *Storage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshTokenData, error) {
	var refreshTokenData models.RefreshTokenData

	query := `
		SELECT id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id
		FROM refresh_tokens
		WHERE token_hash = $1;
	`
	err := s.db.GetContext(ctx, &refreshTokenData, query, tokenHash)
	if err != nil {
		return nil, err
	}
	return &refreshTokenData, nil
}
func (s *Storage) GetRefreshTokenById(ctx context.Context, jwtID uuid.UUID) (*models.RefreshTokenData, error) {
	var refreshTokenData models.RefreshTokenData

	query := `
		SELECT id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id
		FROM refresh_tokens
		WHERE id = $1;
	`
	err := s.db.GetContext(ctx, &refreshTokenData, query, jwtID)
	if err != nil {
		return nil, err
	}
	return &refreshTokenData, nil
}

func (s *Storage) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var User models.User

	query := `SELECT id, email FROM users WHERE id = $1`
	err := s.db.GetContext(ctx, &User, query, userID)
	if err != nil {
		return nil, err
	}

	return &User, nil
}

func (s *Storage) RevokeRefreshToken(ctx context.Context, jwtID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked  = true WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, jwtID)
	return err
}
