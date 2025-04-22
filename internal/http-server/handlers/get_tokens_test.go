package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	mockauth "pas/internal/mock/mock_services_auth"
	"pas/internal/models"
	"pas/internal/services"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetTokensHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	userID := uuid.New()
	expectedTokens := &models.TokenPairs{AccessToken: "access", RefreshToken: "refresh"}

	mockAuth.EXPECT().
		GenerateTokens(gomock.Any(), userID, gomock.Any()).
		Return(expectedTokens, nil)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewGetTokensHandler(log, mockAuth)

	req := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", userID), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.RequestIDKey, "test-id"))
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("user_id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response Response
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokens.AccessToken, response.TokenPairs.AccessToken)
}

func TestGetTokensHandler_InvalidUserID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewGetTokensHandler(log, mockAuth)

	req := httptest.NewRequest("GET", "/tokens/invalid", nil)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("user_id", "invalid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestGetTokensHandler_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	userID := uuid.New()

	mockAuth.EXPECT().
		GenerateTokens(gomock.Any(), userID, gomock.Any()).
		Return(nil, services.ErrUserNotFound)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewGetTokensHandler(log, mockAuth)

	req := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", userID), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.RequestIDKey, "test-id"))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("user_id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
}

func TestRefreshTokensHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	expectedTokens := &models.TokenPairs{AccessToken: "new_access", RefreshToken: "new_refresh"}
	refreshToken := "valid.refresh.token"

	mockAuth.EXPECT().
		RefreshTokens(gomock.Any(), refreshToken, gomock.Any()).
		Return(expectedTokens, nil)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewRefreshTokensHandler(log, mockAuth)

	body := fmt.Sprintf(`{"refresh_token": "%s"}`, refreshToken)
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response Response
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokens.AccessToken, response.TokenPairs.AccessToken)
}

func TestRefreshTokensHandler_InvalidTokenFormat(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewRefreshTokensHandler(log, mockAuth)

	body := `{"refresh_token": "invalid.token"}`
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestRefreshTokensHandler_ExpiredToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuth := mockauth.NewMockAuthService(ctrl)
	refreshToken := "expired.refresh.token"

	mockAuth.EXPECT().
		RefreshTokens(gomock.Any(), refreshToken, gomock.Any()).
		Return(nil, services.ErrExpiredToken)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewRefreshTokensHandler(log, mockAuth)

	body := fmt.Sprintf(`{"refresh_token": "%s"}`, refreshToken)
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name     string
		remote   string
		expected string
	}{
		{"WithPort", "192.168.1.1:8080", "192.168.1.1"},
		{"WithoutPort", "192.168.1.1", "192.168.1.1"},
		{"Invalid", "invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			ip := extractClientIP(req)
			assert.Equal(t, tt.expected, ip)
		})
	}
}
