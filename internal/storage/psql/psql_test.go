package psql

import (
	"context"
	"database/sql"
	"errors"
	"pas/internal/models"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupMockDB(t *testing.T) (*Storage, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	store := New(sqlxDB)

	return store, mock, func() {
		sqlxDB.Close()
	}
}

func TestCreateRefreshToken(t *testing.T) {
	store, mock, close := setupMockDB(t)
	defer close()

	ctx := context.Background()
	token := &models.RefreshTokenData{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: "hash123",
		IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		JWTID:     uuid.New().String(),
	}

	mock.ExpectExec("INSERT INTO refresh_tokens").
		WithArgs(token.ID, token.UserID, token.TokenHash, token.IPAddress,
			token.ExpiresAt, token.CreatedAt, token.Revoked, token.JWTID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := store.CreateRefreshToken(ctx, token)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRefreshToken(t *testing.T) {
	store, mock, close := setupMockDB(t)
	defer close()

	ctx := context.Background()
	userID := uuid.New()
	jwtID := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "user_id", "token_hash", "ip_address", "expires_at", "created_at", "revoked", "jwt_id"}).
		AddRow(uuid.New(), userID, "hash123", "127.0.0.1", time.Now(), time.Now(), false, jwtID)

	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(userID.String(), jwtID.String()).
		WillReturnRows(rows)

	result, err := store.GetRefreshToken(ctx, userID, jwtID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateAndRevokeRefreshToken(t *testing.T) {
	store, mock, close := setupMockDB(t)
	defer close()

	ctx := context.Background()
	oldID := uuid.New()
	newToken := &models.RefreshTokenData{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: "new-hash",
		IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		JWTID:     uuid.New().String(),
	}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO refresh_tokens").
		WithArgs(
			newToken.ID,
			newToken.UserID,
			newToken.TokenHash,
			newToken.IPAddress,
			newToken.ExpiresAt,
			newToken.CreatedAt,
			newToken.Revoked,
			newToken.JWTID,
		).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectExec("UPDATE refresh_tokens SET revoked").
		WithArgs(oldID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err := store.CreateAndRevokeRefreshToken(ctx, newToken, oldID)
	assert.NoError(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetUserByID_Error(t *testing.T) {
	store, mock, close := setupMockDB(t)
	defer close()

	ctx := context.Background()
	userID := uuid.New()

	mock.ExpectQuery("SELECT id, email FROM users WHERE id =").
		WithArgs(userID).
		WillReturnError(errors.New("query error"))

	user, err := store.GetUserByID(ctx, userID)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.EqualError(t, err, "query error")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByIDPass(t *testing.T) {
	store, mock, cleanup := setupMockDB(t)
	defer cleanup()

	userID := uuid.New()
	expectedEmail := "user@example.com"

	rows := sqlmock.NewRows([]string{"id", "email"}).
		AddRow(userID, expectedEmail)

	mock.ExpectQuery(`SELECT id, email FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	ctx := context.Background()
	user, err := store.GetUserByID(ctx, userID)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, expectedEmail, user.Email)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestGetUserByIDNotFound(t *testing.T) {
	store, mock, cleanup := setupMockDB(t)
	defer cleanup()

	userID := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "email"})

	mock.ExpectQuery(`SELECT id, email FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	ctx := context.Background()
	user, err := store.GetUserByID(ctx, userID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, sql.ErrNoRows, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestGetRefreshTokenById(t *testing.T) {
	store, mock, cleanup := setupMockDB(t)
	defer cleanup()

	jwtID := uuid.New()
	userID := uuid.New()
	tokenHash := "someHash"
	ipAddress := "127.0.0.1"
	expiresAt := time.Now().Add(24 * time.Hour)
	createdAt := time.Now()
	revoked := false

	rows := sqlmock.NewRows([]string{
		"id", "user_id", "token_hash", "ip_address", "expires_at", "created_at", "revoked", "jwt_id",
	}).AddRow(
		jwtID, userID, tokenHash, ipAddress, expiresAt, createdAt, revoked, jwtID,
	)

	mock.ExpectQuery(`SELECT id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id FROM refresh_tokens WHERE id = \$1;`).
		WithArgs(jwtID).
		WillReturnRows(rows)

	ctx := context.Background()
	tokenData, err := store.GetRefreshTokenById(ctx, jwtID)
	assert.NoError(t, err)
	assert.NotNil(t, tokenData)
	assert.Equal(t, jwtID, tokenData.ID)
	assert.Equal(t, userID, tokenData.UserID)
	assert.Equal(t, tokenHash, tokenData.TokenHash)
	assert.Equal(t, ipAddress, tokenData.IPAddress)
	assert.WithinDuration(t, expiresAt, tokenData.ExpiresAt, time.Second)
	assert.WithinDuration(t, createdAt, tokenData.CreatedAt, time.Second)
	assert.Equal(t, revoked, tokenData.Revoked)
	assert.Equal(t, jwtID.String(), tokenData.JWTID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRefreshTokenByIdNotFound(t *testing.T) {
	store, mock, cleanup := setupMockDB(t)
	defer cleanup()

	jwtID := uuid.New()

	rows := sqlmock.NewRows([]string{
		"id", "user_id", "token_hash", "ip_address", "expires_at", "created_at", "revoked", "jwt_id",
	})
	mock.ExpectQuery(`SELECT id, user_id, token_hash, ip_address, expires_at, created_at, revoked, jwt_id FROM refresh_tokens WHERE id = \$1;`).
		WithArgs(jwtID).
		WillReturnRows(rows)

	ctx := context.Background()
	tokenData, err := store.GetRefreshTokenById(ctx, jwtID)

	assert.Error(t, err)
	assert.Nil(t, tokenData)
	assert.Equal(t, sql.ErrNoRows, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateAndRevokeRefreshToken_Success(t *testing.T) {
	store, mock, cleanup := setupMockDB(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshTokenData{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: "hash123",
		IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		JWTID:     uuid.New().String(),
	}
	jwtIDToRevoke := uuid.New()

	mock.ExpectBegin()

	mock.ExpectExec(`INSERT INTO refresh_tokens`).
		WithArgs(token.ID, token.UserID, token.TokenHash, token.IPAddress, token.ExpiresAt, token.CreatedAt, token.Revoked, token.JWTID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE id = \$1`).
		WithArgs(jwtIDToRevoke).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err := store.CreateAndRevokeRefreshToken(ctx, token, jwtIDToRevoke)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
