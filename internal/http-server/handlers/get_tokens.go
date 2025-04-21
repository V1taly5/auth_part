package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	resp "pas/internal/lib/api/response"
	"pas/internal/lib/logger/sl"
	"pas/internal/models"
	"pas/internal/services"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type AuthService interface {
	GenerateTokens(ctx context.Context, userID uuid.UUID, ip string) (*models.TokenPairs, error)
	RefreshTokens(ctx context.Context, refreshToken, ip string) (*models.TokenPairs, error)
}

func NewGetTokensHandler(log *slog.Logger, authService AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.get_tokens"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		userIDStr := chi.URLParam(r, "user_id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			log.Error("invalid user_id", slog.String("user_id", userIDStr), sl.Err(err))
			render.JSON(w, r, resp.Error("invalid user ID format"))
			return
		}

		ipAddress := r.RemoteAddr
		tokenPair, err := authService.GenerateTokens(r.Context(), userID, ipAddress)
		if err != nil {
			log.Error("failed to generate tokens", sl.Err(err))
			render.JSON(w, r, resp.Error("internal server error"))
			return
		}
		log.Info("tokens generated successfully", slog.String("user_id", userID.String()))
		render.JSON(w, r, Response{
			resp.OK(),
			*tokenPair,
		})
	}
}

type Response struct {
	resp.Response
	TokenPairs models.TokenPairs `json:"token_pairs"`
}

func NewRefreshTokensHandler(log *slog.Logger, authService AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.refresh_tokens"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req models.RefreshRequest

		if err := render.DecodeJSON(r.Body, &req); err != nil {
			log.Error("failed to decode request body", sl.Err(err))
			render.JSON(w, r, resp.Error("invalid request body"))
			return
		}

		if err := ValidateRefreshToken(req.RefreshToken); err != nil {
			log.Error("invalid validation", sl.Err(err))
			return
		}

		ipAddress := r.RemoteAddr
		tokenPair, err := authService.RefreshTokens(r.Context(), req.RefreshToken, ipAddress)
		if err != nil {
			var statusCode int
			var errMsg string

			switch {
			case errors.Is(err, services.ErrInvalidToken),
				errors.Is(err, services.ErrTokenNotFound),
				errors.Is(err, services.ErrExpiredToken):
				statusCode = http.StatusUnauthorized
				errMsg = ""
			case errors.Is(err, services.ErrTokenAlreadyUsed):
				statusCode = http.StatusForbidden
				errMsg = "token already used"
			case errors.Is(err, services.ErrUserNotFound):
				statusCode = http.StatusNotFound
				errMsg = "user not found"
			default:
				statusCode = http.StatusInternalServerError
				errMsg = "internal server error"
			}
			log.Error("failed to refresh tokens", slog.String("error msg", errMsg), sl.Err(err))
			render.Status(r, statusCode)
			render.JSON(w, r, resp.Error(errMsg))
			return
		}
		log.Info("tokens refreshed successfully")
		render.JSON(w, r, Response{
			resp.OK(),
			*tokenPair,
		})
	}
}

func ValidateRefreshToken(token string) error {
	if token == "" {
		return fmt.Errorf("refresh_token is required")
	}

	if strings.Count(token, ".") != 2 {
		return fmt.Errorf("invalid JWT format")
	}

	return nil
}
