package service

import (
	"net/http"
	"time"

	"github.com/190103385/GO-FINAL.git/domain"
	"github.com/dgrijalva/jwt-go"
)

//Refresh token handler
func Refresh(w http.ResponseWriter, r *http.Request) {
	//Getting cookie from request
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting token string
	tknStr := c.Value

	//Creating claims object
	claims := &domain.Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return domain.JwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
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

	//Can't refresh the token until the condition is met
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 10*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Adding additional time to expiration time
	expirationTime := time.Now().Add(15 * time.Second)

	//Updating expiration time
	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(domain.JwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Setting the cookie with new expiration time
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}