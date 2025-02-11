package handlers

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/jwt/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/ElvinEga/socialmedia/internal/database"
	"github.com/ElvinEga/socialmedia/internal/mail"
)

func Register(c *fiber.Ctx) error {
	type RegisterInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var input RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Generate username from email
	username := strings.ToLower(strings.Split(input.Email, "@")[0])

	// Create user
	user := database.User{
		Username:      username,
		Email:         input.Email,
		Password:      generateHash(input.Password),
		EmailVerified: false,
	}

	// Create user in database
	if err := c.Locals("db").(*gorm.DB).Create(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create user"})
	}

	// Generate verification token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	signedToken, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	// Create verification token
	verificationToken := database.EmailVerificationToken{
		Token:     signedToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Save verification token
	if err := c.Locals("db").(*gorm.DB).Create(&verificationToken).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create verification token"})
	}

	// Send verification email
	if err := mail.SendVerificationEmail(user.Email, signedToken); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to send verification email"})
	}

	return c.JSON(fiber.Map{
		"message": "User registered. Please check your email for verification.",
		"user":    user,
	})
}

func Login(c *fiber.Ctx) error {
	// Implementation omitted for brevity
}

func GoogleLogin(c *fiber.Ctx) error {
	// Implementation omitted for brevity
}

func VerifyEmail(c *fiber.Ctx) error {
	// Implementation omitted for brevity
}

func Logout(c *fiber.Ctx) error {
	// Implementation omitted for brevity
}

func JWTMiddleware(db *gorm.DB) fiber.Handler {
	return jwt.New(jwt.Config{
		SigningKey:  []byte(os.Getenv("JWT_SECRET")),
		Claims:      &jwt.StandardClaims{},
		Cookie:      "access_token",
		TokenLookup: "cookie:access_token",
		SuccessHandler: func(c *fiber.Ctx) error {
			claims := c.Locals("jwt").(*jwt.Token).Claims.(*jwt.StandardClaims)
			userID := c.Locals("user_id").(uuid.UUID)

			// Check password version
			var user database.User
			if err := db.First(&user, userID).Error; err != nil {
				return c.SendStatus(http.StatusUnauthorized)
			}

			if user.PasswordVersion != claims.Get("password_version").(int) {
				return c.SendStatus(http.StatusUnauthorized)
			}

			return c.Next()
		},
	})
}
