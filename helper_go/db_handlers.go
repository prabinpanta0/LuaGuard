package main

import (
	"crypto/rand"
	"encoding/hex" // Added for environment variables
	"regexp"       // Added for email validation
)

// --- Structs ---

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginSuccessResponse struct {
	Message      string `json:"message"`
	SessionToken string `json:"session_token,omitempty"` // Only if MFA not required
	MFARequired  bool   `json:"mfa_required"`
}

// Added for password reset request
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// Added for password reset execution
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// --- Helper Functions ---

// generateSecureToken creates a cryptographically secure random token.
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// isValidEmail checks if the email format is valid.
func isValidEmail(email string) bool {
	// A common regex for email validation (adjust complexity as needed)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// --- Handlers ---

// This file previously contained authentication/session logic for a standalone Go backend.
// It is now deprecated: all authentication, session, and MFA logic is handled in Lua.
// This file is retained for reference only. All Go helper endpoints are now in main.go, hash.go, email.go, recaptcha.go, and mfa_handlers.go.

// --- All handler and DB logic removed. Use Lua as the main server. ---
