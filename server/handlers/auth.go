package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/ElvinEga/socialmedia/internal/database"
	"github.com/ElvinEga/socialmedia/internal/mail"
)

// CustomClaims defines the JWT claims used in our application.
type CustomClaims struct {
	UserID          string `json:"user_id"`
	PasswordVersion int    `json:"password_version,omitempty"`
	jwt.RegisteredClaims
}

// Register creates a new user, sends an email verification, and stores a verification token.
func Register(c *fiber.Ctx) error {
	type RegisterInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var input RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Generate username from email.
	username := strings.ToLower(strings.Split(input.Email, "@")[0])

	// Check if email already exists.
	var count int64
	db := c.Locals("db").(*gorm.DB)
	db.Model(&database.User{}).Where("email = ?", input.Email).Count(&count)
	if count > 0 {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email already registered"})
	}

	// Hash the password.
	hashedPassword := generateHash(input.Password)

	// Create the user.
	user := database.User{
		Username:      username,
		Email:         input.Email,
		Password:      hashedPassword,
		EmailVerified: false,
	}

	if err := db.Create(&user).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	// Generate a verification token.
	verificationTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	signedToken, err := verificationTokenJWT.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to sign verification token"})
	}

	// Save the verification token in the database.
	verificationToken := database.EmailVerificationToken{
		Token:     signedToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := db.Create(&verificationToken).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create verification token"})
	}

	// Send the verification email.
	if err := mail.SendVerificationEmail(user.Email, signedToken); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send verification email"})
	}

	return c.JSON(fiber.Map{
		"message": "User registered. Please check your email for verification.",
		"user":    user,
	})
}

// Login verifies user credentials, generates a JWT, and sets it as a cookie.
func Login(c *fiber.Ctx) error {
	type LoginInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var input LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	db := c.Locals("db").(*gorm.DB)

	// Find user by email.
	var user database.User
	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Verify password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid password"})
	}

	// Generate JWT token with custom claims.
	claims := CustomClaims{
		UserID:          user.ID.String(),
		PasswordVersion: user.PasswordVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(), // This acts as the JWT ID (jti).
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	// Set token in an HTTP-only cookie.
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
	})

	return c.JSON(fiber.Map{"message": "Logged in successfully"})
}

// GoogleLogin redirects the user to Google for OAuth2 authentication.
func GoogleLogin(c *fiber.Ctx) error {
	redirectURL := "https://accounts.google.com/o/oauth2/auth?client_id=" + os.Getenv("GOOGLE_CLIENT_ID") +
		"&redirect_uri=" + os.Getenv("GOOGLE_REDIRECT_URL") +
		"&scope=openid%20email%20profile&response_type=code&access_type=offline"
	return c.Redirect(redirectURL)
}

// GoogleCallback handles the OAuth2 callback from Google.
func GoogleCallback(c *fiber.Ctx) error {
	// Here you would exchange the code for an access token, get user info, create/find the user,
	// generate your JWT, set it as a cookie, etc.
	code := c.Query("code")
	return c.JSON(fiber.Map{"message": "Google login successful", "code": code})
}

// VerifyEmail checks the email verification token and marks the user's email as verified.
func VerifyEmail(c *fiber.Ctx) error {
	tokenString := c.Params("token")

	db := c.Locals("db").(*gorm.DB)

	var tokenRecord database.EmailVerificationToken
	if err := db.First(&tokenRecord, "token = ?", tokenString).Error; err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	if tokenRecord.ExpiresAt.Before(time.Now()) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Token expired"})
	}

	var user database.User
	if err := db.First(&user, tokenRecord.UserID).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
	}

	user.EmailVerified = true
	db.Save(&user)
	db.Delete(&tokenRecord)

	return c.JSON(fiber.Map{"message": "Email verified successfully"})
}

// Logout revokes the JWT (by saving its jti in a revocation list) and clears the cookie.
func Logout(c *fiber.Ctx) error {
	claims, ok := c.Locals("jwt_claims").(*CustomClaims)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid JWT claims"})
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user id"})
	}

	revokedToken := database.RevokedToken{
		JTI:    claims.ID,
		UserID: userID,
	}

	db := c.Locals("db").(*gorm.DB)
	if err := db.Create(&revokedToken).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not revoke token"})
	}

	c.ClearCookie("access_token")
	return c.JSON(fiber.Map{"message": "Logged out"})
}

// JWTMiddleware is a custom middleware that validates the JWT from the cookie and sets user info in locals.
func JWTMiddleware(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from cookie.
		tokenString := c.Cookies("access_token")
		if tokenString == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or malformed JWT"})
		}

		// Parse token.
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid JWT: " + err.Error()})
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok || !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid JWT claims"})
		}

		// Check token expiration.
		if claims.ExpiresAt.Time.Before(time.Now()) {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "JWT expired"})
		}

		// Retrieve the user from the database.
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user id in token"})
		}
		var user database.User
		if err := db.First(&user, "id = ?", userID).Error; err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
		}

		// Optionally, check if the user's password has changed (by comparing the password version).
		if user.PasswordVersion != claims.PasswordVersion {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Token invalid due to password change"})
		}

		// (Optional) Check if the token has been revoked using your RevokedToken table.

		// Set the user and claims in the context for use in subsequent handlers.
		c.Locals("user", user)
		c.Locals("jwt_claims", claims)

		return c.Next()
	}
}

// generateHash creates a SHA-256 hash of the password combined with a salt (here, using the JWT secret).
func generateHash(password string) string {
	salt := os.Getenv("JWT_SECRET")
	hash := sha256.Sum256([]byte(password + salt))
	return base64.StdEncoding.EncodeToString(hash[:])
}
