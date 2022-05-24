package service

import (
	"fmt"
	"net/http"

	"github.com/190103385/GO-FINAL.git/domain"

	"github.com/dgrijalva/jwt-go"
)

//Home page handler
func Home(w http.ResponseWriter, r *http.Request) {
	//Getting cookie from request
	cookie, err := r.Cookie("token")
	
	if(err != nil) {
		if(err == http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting token string
	tokenStr := cookie.Value

	//Creating claims var
	claims := &domain.Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return domain.JwtKey, nil
	})

	if(err != nil) {
		if(err == jwt.ErrSignatureInvalid) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Hurray, we reached the home page!
	w.Write([]byte(fmt.Sprintf("Hello %s", claims.Username)))
}