package main

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

//Key for JWT token
var jwtKey = []byte("secret_key")

//User credential's type
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//Claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}


func Login(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Login"))
}


func Register(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Register"))
}


func Refresh(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Refresh"))
}


func Home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Home"))
}