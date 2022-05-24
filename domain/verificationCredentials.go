package domain

type VerificationCredentials struct {
	Username         string `json:"username"`
	VerificationCode string `json:"verificationCode"`
}