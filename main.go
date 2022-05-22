package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

//DB credentials
const(
	host     = "localhost"
	port     =  5432
	user     = "postgres"
	password = "postgreadmin"
	dbname   = "go_final"
)

var db *sql.DB

func main() {
	//DB connection establishing
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s "+
    "password=%s dbname=%s sslmode=disable",
    host, port, user, password, dbname)

	var err error

	db, err = sql.Open("postgres", psqlconn)
	
	if err != nil {
  		panic(err)
	}
	
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Connection established")

	//Handlers
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/home", Home)
	http.HandleFunc("/refresh", Refresh)

	//Serve port 8080
	log.Fatal(http.ListenAndServe(":8080", nil))
}