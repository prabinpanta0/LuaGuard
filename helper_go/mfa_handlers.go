package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
)

// --- MFA Structs ---
type MFASetupResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
	Error           string `json:"error,omitempty"`
}

type MFAVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type MFAVerifyResponse struct {
	Success      bool   `json:"success"`
	SessionToken string `json:"session_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// --- MFA Handlers ---
func HandleMFASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Only POST method is allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	if req.Email == "" {
		http.Error(w, `{"error": "Email is required for MFA setup"}`, http.StatusBadRequest)
		return
	}
	issuer := "MyApp"
	accountName := req.Email
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		log.Printf("Error generating TOTP key for %s: %v", req.Email, err)
		json.NewEncoder(w).Encode(MFASetupResponse{Error: "Failed to generate MFA secret"})
		return
	}
	updatePendingSecretSQL := `UPDATE users SET pending_mfa_secret = $1, mfa_enabled = FALSE WHERE email = $2`
	_, err = dbpool.Exec(context.Background(), updatePendingSecretSQL, key.Secret(), req.Email)
	if err != nil {
		log.Printf("Error storing pending MFA secret for %s: %v", req.Email, err)
		json.NewEncoder(w).Encode(MFASetupResponse{Error: "Failed to save MFA secret"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(MFASetupResponse{
		Secret:          key.Secret(),
		ProvisioningURL: key.URL(),
	})
}

func HandleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Only POST method is allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	if req.Email == "" || req.Code == "" {
		http.Error(w, `{"error": "Email and MFA code are required"}`, http.StatusBadRequest)
		return
	}
	var pendingSecret sql.NullString
	var confirmedSecret sql.NullString
	var mfaEnabled bool
	getSecretsSQL := `SELECT pending_mfa_secret, mfa_secret, mfa_enabled FROM users WHERE email = $1`
	err := dbpool.QueryRow(context.Background(), getSecretsSQL, req.Email).Scan(&pendingSecret, &confirmedSecret, &mfaEnabled)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		} else {
			log.Printf("Error retrieving MFA secrets for %s: %v", req.Email, err)
			http.Error(w, `{"error": "Database error during MFA verification"}`, http.StatusInternalServerError)
		}
		return
	}
	var secretToValidate string
	verifyingSetup := false
	if pendingSecret.Valid && pendingSecret.String != "" {
		secretToValidate = pendingSecret.String
		verifyingSetup = true
	} else if mfaEnabled && confirmedSecret.Valid && confirmedSecret.String != "" {
		secretToValidate = confirmedSecret.String
	} else {
		http.Error(w, `{"error": "MFA is not active or pending setup for this account"}`, http.StatusBadRequest)
		return
	}
	valid := totp.Validate(req.Code, secretToValidate)
	if !valid {
		http.Error(w, `{"error": "Invalid MFA code"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if verifyingSetup {
		activateMFASQL := `UPDATE users SET mfa_secret = $1, mfa_enabled = TRUE, pending_mfa_secret = NULL WHERE email = $2`
		_, err = dbpool.Exec(context.Background(), activateMFASQL, secretToValidate, req.Email)
		if err != nil {
			json.NewEncoder(w).Encode(MFAVerifyResponse{Success: false, Error: "Failed to activate MFA"})
			return
		}
		json.NewEncoder(w).Encode(MFAVerifyResponse{Success: true})
	} else {
		sessionToken, err := generateSecureToken(32)
		if err != nil {
			json.NewEncoder(w).Encode(MFAVerifyResponse{Success: false, Error: "Failed to create session"})
			return
		}
		sessionExpiresAt := time.Now().Add(1 * time.Hour)
		insertSessionSQL := `INSERT INTO sessions (token, email, expires_at) VALUES ($1, $2, $3)`
		_, err = dbpool.Exec(context.Background(), insertSessionSQL, sessionToken, req.Email, sessionExpiresAt)
		if err != nil {
			json.NewEncoder(w).Encode(MFAVerifyResponse{Success: false, Error: "Failed to store session"})
			return
		}
		json.NewEncoder(w).Encode(MFAVerifyResponse{Success: true, SessionToken: sessionToken})
	}
}
