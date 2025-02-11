func jwtware(c *fiber.Ctx) error {
	return jwt.New(jwt.Config{
		SigningKey:  []byte(os.Getenv("JWT_SECRET")),
		Claims:      &jwt.StandardClaims{},
		Cookie:      "access_token",
		TokenLookup: "cookie:access_token",
		SuccessHandler: func(c *fiber.Ctx) error {
			claims := c.Locals("jwt").(*jwt.Token).Claims.(*jwt.StandardClaims)
			user_id := uuid.MustParse(claims.Get("user_id").(string))
			password_version := claims.Get("password_version").(int)

			// Check password version
			var user User
			db.First(&user, user_id)
			if user.PasswordVersion != password_version {
				return c.SendStatus(fiber.StatusUnauthorized)
			}

			return c.Next()
		},
	}).Parser()(c)
}