package service

import (
	"fmt"
	"net/mail"
	"net/smtp"
)

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)

	return err == nil
}

func sendEmailTo(to string, msg string) error {
	from := "octodad48@gmail.com"
	password := "SPECIALFORGOLANG1"

	receiver := []string{
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