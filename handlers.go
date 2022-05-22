package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
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
}

//Claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}


//Login handler
func Login(w http.ResponseWriter, r *http.Request) {
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
	fmt.Fprintf(w, "Login auth success")
}


//Register handler
func Register(w http.ResponseWriter, r *http.Request) {
	//Creating credentials's var
	var creds Credentials

	//Decode request's body into creds var
	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Getting username and password from request
	username := creds.Username
	password := creds.Password

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

	//Create hash from password
	var hash []byte
	hash,err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//SQL statement for inserting new record
	var insertStmt *sql.Stmt
	insertStmt, err = db.Prepare("INSERT INTO users (username, password) VALUES ($1, $2);")
	
	if err != nil {
		fmt.Println("Error preparing statement, err: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer insertStmt.Close()

	var result sql.Result

	result, err = insertStmt.Exec(username, hash)
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
func Refresh(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Refresh"))
}


//Home page handler
func Home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Home"))
}