package controllers

import (
	"net/http"

	"github.com/190103385/GO-FINAL.git/service"
)

func BuildRouters() {
	//Handlers
	http.HandleFunc("/register", service.Register)
	http.HandleFunc("/login", service.Login)
	http.HandleFunc("/home", service.Home)
	http.HandleFunc("/refresh", service.Refresh)
	http.HandleFunc("/verifyEmail", service.VerifyEmail)
	http.HandleFunc("/changePass", service.ChangePassword)
}