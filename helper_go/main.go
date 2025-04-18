package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	qrcode "github.com/skip2/go-qrcode"
)

var dbpool *pgxpool.Pool

func initDB() {
	// Load .env file
	err := godotenv.Load("../.env") // Load from parent directory
	if err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	dbpool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	// Create tables if they don't exist
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		email TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		verified BOOLEAN DEFAULT FALSE,
		mfa_secret TEXT,
		pending_mfa_secret TEXT,
		mfa_enabled BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL
	);

	CREATE TABLE IF NOT EXISTS verification_tokens (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL
	);

	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL
	);

	CREATE TABLE IF NOT EXISTS rate_limits (
		key TEXT PRIMARY KEY,
		count INTEGER NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL
	);
	`
	_, err = dbpool.Exec(context.Background(), createTablesSQL)
	if err != nil {
		log.Fatalf("Unable to create tables: %v\n", err)
	}
	log.Println("Database connected and schema initialized.")
}

type qrCodeRequest struct {
	URL string `json:"url"`
}

type qrCodeResponse struct {
	DataURL string `json:"data_url,omitempty"`
	Error   string `json:"error,omitempty"`
}

func qrCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req qrCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.URL == "" {
		http.Error(w, "Missing 'url' in request", http.StatusBadRequest)
		return
	}

	// Generate QR code PNG data
	png, err := qrcode.Encode(req.URL, qrcode.Medium, 256) // Medium error correction, 256x256 pixels
	if err != nil {
		log.Printf("Error generating QR code: %v", err)
		json.NewEncoder(w).Encode(qrCodeResponse{Error: "Failed to generate QR code"})
		return
	}

	// Encode PNG data as base64 data URL
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(qrCodeResponse{DataURL: dataURL})
}

func main() {
	initDB()
	defer dbpool.Close()

	// Handlers from dedicated files
	http.HandleFunc("/hash", HandleHash)
	http.HandleFunc("/recaptcha", HandleRecaptcha)
	http.HandleFunc("/email", HandleEmail)
	http.HandleFunc("/qrcode", qrCodeHandler)

	// Handlers from db_handlers.go
	// http.HandleFunc("/register", HandleRegister)
	// http.HandleFunc("/login", HandleLogin)
	// http.HandleFunc("/logout", HandleLogout)
	// http.HandleFunc("/verify-email", HandleVerifyEmail)
	// http.HandleFunc("/request-password-reset", HandleRequestPasswordReset)
	// http.HandleFunc("/reset-password", HandleResetPassword)
	http.HandleFunc("/mfa-setup", HandleMFASetup)
	http.HandleFunc("/mfa-verify", HandleMFAVerify)
	// Add other DB related handlers as needed

	log.Println("Go helper listening on :8081")
	http.ListenAndServe(":8081", nil)
}
