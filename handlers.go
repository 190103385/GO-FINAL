package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

//Key for JWT token
var jwtKey = []byte("secret_key")

//User credential's type
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type VerificationCredentials struct {
	Username 		 string `json:"username"`
	VerificationCode string `json:"verificationCode"`
}

type PasswordChangeCredentials struct {
	Username 	string `json:"username"`
	Password 	string `json:"password"`
	NewPassword string `json:"newPassword"`
}

//Claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}


//Login handler
func login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

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

	row := db.QueryRow(stmt, username)
	
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
	claims := Claims {
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//Creating a token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//Getting token signed string with JWT key
	tokenString, err := token.SignedString(jwtKey)
	
	if(err != nil) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Setting the cookie with name "token"
	http.SetCookie(w, 
		&http.Cookie {
			Name: "token",
			Value: tokenString,
			Expires: expirationTime,
		})

	//Hurray, login succes!
	w.Write([]byte("Login auth success"))
}


//Register handler
func register(w http.ResponseWriter, r *http.Request) {
	//Creating credentials's var
	var creds Credentials

	//Decode request's body into creds var
	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting username, password and email from request
	username := creds.Username
	password := creds.Password
	email    := creds.Email

	//Checking if username already exists
	
	//SQL statement for getting user id with given username 
	stmt := "SELECT id FROM users WHERE username = $1"
	
	//Passing username and getting result row
	row := db.QueryRow(stmt, username)

	//User ID var
	var uId string
	err = row.Scan(uId)
	if err != sql.ErrNoRows {
		fmt.Println("Username already exists")
		w.WriteHeader(http.StatusConflict)
		return
	}

	//Checking if email is valid
	if(!isValidEmail(email)) {
		fmt.Println("Email is invalid")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Random verification code
	verificationCode := generateVerificationCode(8)

	//Sending emaul with verification code to user email
	err = sendEmailTo(email, verificationCode)
	
	if err != nil {
		fmt.Println("Couldn't send verification code")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Create hash from password
	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//SQL statement for inserting new record
	var insertStmt *sql.Stmt
	insertStmt, err = db.Prepare("INSERT INTO users (username, password, email, verification_code) VALUES ($1, $2, $3, $4);")
	
	if err != nil {
		fmt.Println("Error preparing statement, err: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer insertStmt.Close()

	var result sql.Result

	result, err = insertStmt.Exec(username, hash, email, verificationCode)
	rowsAff, _ := result.RowsAffected()

	fmt.Println("Rows affected: ", rowsAff)

	if err != nil {
		fmt.Println("Couldn't register new user")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Hurray, registration is successfull!
	w.Write([]byte(fmt.Sprintf("Congratulations %s, your account registered successfully", username)))
}


//Refresh token handler
func refresh(w http.ResponseWriter, r *http.Request) {
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
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
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

	tokenString, err := token.SignedString(jwtKey)
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


//Home page handler
func home(w http.ResponseWriter, r *http.Request) {
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
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
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


//Email verification handler
func verifyEmail(w http.ResponseWriter, r *http.Request) {
	var creds VerificationCredentials

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
	row := db.QueryRow(stmt, username)
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
	_, err = db.Exec(stmt, true, username)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Hurray, email is verified!
	w.Write([]byte("Email is verified"))
}


//Change password handler
func changePassword(w http.ResponseWriter, r *http.Request) {
	//Password var
	var creds PasswordChangeCredentials

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
	row := db.QueryRow(stmt, username)
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
	_, err = db.Exec(stmt, hash, username)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)

    return err == nil	
}

func sendEmailTo(to string, msg string) error {
	from := "octodad48@gmail.com"
	password := "SPECIALFORGOLANG1"

	receiver := []string {
		to,
	}

	message := []byte(msg)
  
	// smtp server configuration.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Sending email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, receiver, message)
	if err != nil {
	  fmt.Println(err)
	  return err
	}

	return nil
}

func generateVerificationCode(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}