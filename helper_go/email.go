package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
)

type EmailRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type EmailResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func HandleEmail(w http.ResponseWriter, r *http.Request) {
	var req EmailRequest
	json.NewDecoder(r.Body).Decode(&req)
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	msg := []byte("To: " + req.To + "\r\n" +
		"Subject: " + req.Subject + "\r\n" +
		"\r\n" + req.Body + "\r\n")
	err := smtp.SendMail(addr, auth, smtpUser, []string{req.To}, msg)
	if err != nil {
		json.NewEncoder(w).Encode(EmailResponse{Success: false, Error: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(EmailResponse{Success: true})
}
