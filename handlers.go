package main

import (
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Login"))
}

func Register(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Register"))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Refresh"))
}

func Home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Home"))
}