package handler

import "net/http"

func (h *Handler) SetRoutes(router *http.ServeMux) {
	// Provider login handler
	router.HandleFunc("GET /auth/login/{provider}", h.HandleLogin)

	// OAuth2 callback function. This creates the refresh token for the authenticated user
	router.HandleFunc("POST /auth/callback/{provider}", h.HandleCallback)

	// Refres expiring access token
	router.HandleFunc("POST /auth/refresh", h.HandleRefresh)

	// Get access token verification key
	// This is used by the server to verify incoming access tokens
	router.HandleFunc("GET /auth/verification-key", h.GetPublicKey)
}
