func Register(c *fiber.Ctx) error {
	// User registration logic
	// ...
	// Send verification email
	token := generateToken(user.ID)
	verificationToken := EmailVerificationToken{
		Token:     token,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(&verificationToken)
	mail.SendVerificationEmail(user.Email, token)
}

func VerifyEmail(c *fiber.Ctx) error {
	// Email verification logic
}

func GoogleLogin(c *fiber.Ctx) error {
	// Google SSO login handler
	// Automatically sets EmailVerified = true
}

func Logout(c *fiber.Ctx) error {
	// JWT logout logic
	revokedToken := RevokedToken{
		JTI:    claims.Get("jti").(string),
		UserID: userID,
	}
	db.Create(&revokedToken)
}