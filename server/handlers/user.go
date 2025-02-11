package handlers

import (
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/ElvinEga/socialmedia/internal/database"
)

func UpdateProfile(c *fiber.Ctx) error {
	user := c.Locals("user").(database.User)

	type UpdateInput struct {
		Username       *string `json:"username,omitempty"`
		Email          *string `json:"email,omitempty"`
		Bio            *string `json:"bio,omitempty"`
		ProfilePicture *string `json:"profile_picture,omitempty"`
	}

	var input UpdateInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Update username
	if input.Username != nil {
		if user.Username != *input.Username {
			var count int64
			c.Locals("db").(*gorm.DB).Model(&database.User{}).Where("username = ?", *input.Username).Count(&count)
			if count > 0 {
				return c.Status(400).JSON(fiber.Map{"error": "Username already taken"})
			}
			user.Username = *input.Username
		}
	}

	// Update email (only for local accounts)
	if input.Email != nil && user.Provider == "local" {
		if user.Email != *input.Email {
			var count int64
			c.Locals("db").(*gorm.DB).Model(&database.User{}).Where("email = ?", *input.Email).Count(&count)
			if count > 0 {
				return c.Status(400).JSON(fiber.Map{"error": "Email already taken"})
			}
			user.Email = *input.Email
			user.EmailVerified = false
		}
	}

	// Update bio
	if input.Bio != nil {
		user.Bio = *input.Bio
	}

	// Update profile picture
	if input.ProfilePicture != nil {
		user.ProfilePicture = *input.ProfilePicture
	}

	if err := c.Locals("db").(*gorm.DB).Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update profile"})
	}

	return c.JSON(user)
}

func ChangePassword(c *fiber.Ctx) error {
	user := c.Locals("user").(database.User)

	type PasswordInput struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	var input PasswordInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.CurrentPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid current password"})
	}

	// Update password
	user.Password = generateHash(input.NewPassword)
	user.PasswordVersion++

	if err := c.Locals("db").(*gorm.DB).Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.JSON(fiber.Map{"message": "Password updated successfully"})
}
