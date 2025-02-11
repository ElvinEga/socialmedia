package handlers

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"socialmedia/internal/database"
)

func CreatePost(c *fiber.Ctx) error {
	user := c.Locals("user").(database.User)

	type PostInput struct {
		Content string `json:"content"`
	}

	var input PostInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	post := database.Post{
		UserID:  user.ID,
		Content: input.Content,
	}

	if err := c.Locals("db").(*gorm.DB).Create(&post).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create post"})
	}

	return c.JSON(post)
}

func GetTimeline(c *fiber.Ctx) error {
	user := c.Locals("user").(database.User)

	var posts []database.Post
	c.Locals("db").(*gorm.DB).Preload("User").Joins(
		"LEFT JOIN user_followers ON user_followers.user_id = ? AND user_followers.followed_id = posts.user_id",
		user.ID,
	).Where("posts.user_id = ? OR (posts.user_id IN (SELECT followed_id FROM user_followers WHERE user_id = ?))",
		user.ID, user.ID,
	).Order("posts.created_at DESC").Find(&posts)

	return c.JSON(posts)
}

func GetPost(c *fiber.Ctx) error {
	postID := c.Params("id")

	var post database.Post
	if err := c.Locals("db").(*gorm.DB).Preload("User").First(&post, postID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Post not found"})
	}

	return c.JSON(post)
}

func DeletePost(c *fiber.Ctx) error {
	postID := c.Params("id")
	user := c.Locals("user").(database.User)

	var post database.Post
	if err := c.Locals("db").(*gorm.DB).First(&post, postID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Post not found"})
	}

	if post.UserID != user.ID {
		return c.Status(403).JSON(fiber.Map{"error": "Unauthorized"})
	}

	if err := c.Locals("db").(*gorm.DB).Delete(&post).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete post"})
	}

	return c.JSON(fiber.Map{"message": "Post deleted successfully"})
}
