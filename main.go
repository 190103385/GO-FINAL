package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	controller "github.com/190103385/GO-FINAL.git/controller"
	"github.com/190103385/GO-FINAL.git/repository"
	_ "github.com/lib/pq"
)

//DB credentials
const(
	host     = "database"
	port     =  5432
	user     = "postgres"
	password = "postgreadmin"
	dbname   = "go_final"
)

func main() {
	//DB connection establishing
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s "+
    "password=%s dbname=%s sslmode=disable",
    host, port, user, password, dbname)

	var err error

	repository.DB, err = sql.Open("postgres", psqlconn)
	
	if err != nil {
  		panic(err)
	}
	
	defer repository.DB.Close()

	err = repository.DB.Ping()
	if err != nil {
		panic(err)
	}

	repository.DB.Exec("CREATE TABLE IF NOT EXISTS users (id serial, username text NOT NULL, password text NOT NULL, email text NOT NULL, is_valid boolean NOT NULL DEFAULT false, verification_code text, PRIMARY KEY (id))")

	fmt.Println("Connection established")

	//Building routes
	controller.BuildRouters()

	//Serve port 8080
	log.Fatal(http.ListenAndServe(":8080", nil))
}