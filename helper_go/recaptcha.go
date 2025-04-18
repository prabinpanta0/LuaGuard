package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type RecaptchaRequest struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

type RecaptchaResponse struct {
	Success bool    `json:"success"`
	Score   float64 `json:"score,omitempty"`
	Error   string  `json:"error,omitempty"`
}

func HandleRecaptcha(w http.ResponseWriter, r *http.Request) {
	var req RecaptchaRequest
	json.NewDecoder(r.Body).Decode(&req)
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify",
		map[string][]string{
			"secret":   {req.Secret},
			"response": {req.Token},
		},
	)
	if err != nil {
		json.NewEncoder(w).Encode(RecaptchaResponse{Success: false, Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}
