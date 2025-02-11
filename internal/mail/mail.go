func SendVerificationEmail(email, token string) error {
	// SMTP configuration from internal/config/config.go
	cfg := config.GetConfig()

	msg := &email.Message{
		Headers: email.Headers{
			"From":    "noreply@example.com",
			"To":      email.Address(email, ""),
			"Subject": "Verify Your Email",
		},
		Body: fmt.Sprintf("Verify your email: http://localhost:8000/verify-email/%s", token),
	}

	return email.NewSMTPClient(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUser,
		cfg.SMTPPassword,
	).Send(msg)
}