package main

import (
	"encoding/json"
	"net/http"
	"golang.org/x/crypto/argon2"
	"crypto/rand"
	"encoding/base64"
)

type HashRequest struct {
	Password string `json:"password"`
	Salt     string `json:"salt,omitempty"`
}
type HashResponse struct {
	Hash string `json:"hash"`
	Salt string `json:"salt"`
}

func randomSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func argon2idHash(password, salt string) string {
	saltBytes, _ := base64.RawStdEncoding.DecodeString(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(hash)
}

func HandleHash(w http.ResponseWriter, r *http.Request) {
	var req HashRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Salt == "" {
		req.Salt = randomSalt()
	}
	hash := argon2idHash(req.Password, req.Salt)
	json.NewEncoder(w).Encode(HashResponse{Hash: hash, Salt: req.Salt})
}
