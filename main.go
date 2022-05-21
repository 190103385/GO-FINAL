package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const(
	host     = "localhost"
	port     =  5432
	user     = "postgres"
	password = "postgreadmin"
	dbname   = "go_final"
)

type User struct {
	Id       int
	Username string
	Password string
}

func main() {
	//DB connection establishing
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s "+
    "password=%s dbname=%s sslmode=disable",
    host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlconn)
	
	if err != nil {
  		panic(err)
	}
	
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Connection established")

	//Checking by retrieving record from "users" table
	stmt := "SELECT username FROM users WHERE id = $1"
	row := db.QueryRow(stmt, 8)

	var username string

	err = row.Scan(&username)
	if err != nil {
		fmt.Println("Couldn't get the user")
	}

	fmt.Println(username)
}