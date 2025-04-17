package httpserver

import (
	"log/slog"
	"pas/internal/http-server/handlers"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func SetupRoutes(log *slog.Logger, servvice handlers.AuthService) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Get("tokens/{user_id}", handlers.NewGetTokensHandler(log, servvice))
			r.Post("/refresh", handlers.NewRefreshTokensHandler(log, servvice))
		})
	})
	return r
}
