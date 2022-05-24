package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/190103385/GO-FINAL.git/domain"
	"github.com/190103385/GO-FINAL.git/repository"
)

//Email verification handler
func VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var creds domain.VerificationCredentials

	//Decode request's body into creds var
	err := json.NewDecoder(r.Body).Decode(&creds)

	//Getting username and verification code from request
	username := creds.Username
	verificationCode := creds.VerificationCode

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting verification code from db using username
	var expVerificationCode string
	stmt := "SELECT verification_code FROM users WHERE username = $1"
	row := repository.DB.QueryRow(stmt, username)
	err = row.Scan(&expVerificationCode)

	if err != nil {
		fmt.Printf("No such user: %s\n", username)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if(verificationCode != expVerificationCode) {
		fmt.Println("Codes doesn't match")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stmt = "UPDATE users SET is_valid = $1 WHERE username = $2"
	_, err = repository.DB.Exec(stmt, true, username)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Hurray, email is verified!
	w.Write([]byte("Email is verified"))
}