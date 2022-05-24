package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/190103385/GO-FINAL.git/domain"
	"github.com/190103385/GO-FINAL.git/repository"
	"golang.org/x/crypto/bcrypt"
)

//Register handler
func Register(w http.ResponseWriter, r *http.Request) {
	//Creating credentials's var
	var creds domain.Credentials

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
	row := repository.DB.QueryRow(stmt, username)

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
	insertStmt, err = repository.DB.Prepare("INSERT INTO users (username, password, email, verification_code) VALUES ($1, $2, $3, $4);")
	
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