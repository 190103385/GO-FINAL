package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/190103385/GO-FINAL.git/domain"
	"github.com/190103385/GO-FINAL.git/repository"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func Login(w http.ResponseWriter, r *http.Request) {
	var creds domain.Credentials

	//Decode request's body into creds var
	err := json.NewDecoder(r.Body).Decode(&creds)

	//Getting username and password from request
	username := creds.Username
	password := creds.Password

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting hashed password from db using username
	var hash string

	stmt := "SELECT password FROM users WHERE username = $1"

	row := repository.DB.QueryRow(stmt, username)

	err = row.Scan(&hash)

	if err != nil {
		fmt.Println("No such user")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Compare hashed password from db and password from user input
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	if err != nil {
		fmt.Println("Passwords not match")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Creating exipration time var with 15 seconds
	expirationTime := time.Now().Add(time.Second * 15)

	//Creating claims and passing expiration time
	claims := domain.Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//Creating a token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//Getting token signed string with JWT key
	tokenString, err := token.SignedString(domain.JwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Setting the cookie with name "token"
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

	//Hurray, login succes!
	w.Write([]byte("Login auth success"))
}