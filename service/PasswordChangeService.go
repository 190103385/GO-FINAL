package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/190103385/GO-FINAL.git/domain"
	"github.com/190103385/GO-FINAL.git/repository"
	"golang.org/x/crypto/bcrypt"
)

//Change password handler
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	//Password var
	var creds domain.PasswordChangeCredentials

	//Decode request's body into creds var
	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username 	:= creds.Username
	password 	:= creds.Password
	newPassword := creds.NewPassword

	var dbPassword string
	stmt := "SELECT password FROM users WHERE username = $1"
	row := repository.DB.QueryRow(stmt, username)
	err = row.Scan(&dbPassword)

	if err != nil {
		fmt.Println("No such user")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Compare hashed password from db and password from user input
	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))

	if err != nil {
		fmt.Println("Passwords doesn't match")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	stmt = "UPDATE users SET password = $1 WHERE username = $2"
	_, err = repository.DB.Exec(stmt, hash, username)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}