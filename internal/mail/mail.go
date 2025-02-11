package mail

import (
	"gopkg.in/gomail.v2"
)

func SendVerificationEmail(email, token string) error {
	// SMTP configuration
	cfg := config.GetConfig()
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.SMTPUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Verify Your Email")
	m.SetBody("text/html", "Verify your email: http://localhost:8000/verify-email/"+token)

	// Send email
	return gomail.NewDialer(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUser,
		cfg.SMTPPassword,
	).DialAndSend(m)
}
