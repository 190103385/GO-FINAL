package domain

import "github.com/dgrijalva/jwt-go"

//Claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}