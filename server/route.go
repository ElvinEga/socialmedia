package server

import (
	"github.com/ElvinEga/socialmedia/server/handlers"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func SetupRoutes(app *fiber.App, db *gorm.DB) {
	// Public routes
	app.Post("/auth/register", handlers.Register)
	app.Post("/auth/login", handlers.Login)
	app.Get("/auth/google", handlers.GoogleLogin)
	app.Get("/auth/google/callback", handlers.GoogleCallback)
	// app.Get("/auth/github", handlers.GitHubLogin)
	// app.Get("/auth/github/callback", handlers.GitHubCallback)
	app.Get("/verify-email/:token", handlers.VerifyEmail)

	// Protected routes for user-related operations
	userGroup := app.Group("/users", handlers.JWTMiddleware(db))
	userGroup.Put("/me", handlers.UpdateProfile)
	userGroup.Put("/password", handlers.ChangePassword)
	userGroup.Post("/logout", handlers.Logout)

	// Protected routes for posts-related operations
	postsGroup := app.Group("/posts", handlers.JWTMiddleware(db))
	postsGroup.Post("/", handlers.CreatePost)
	postsGroup.Get("/", handlers.GetTimeline)
	postsGroup.Get("/:id", handlers.GetPost)
	postsGroup.Delete("/:id", handlers.DeletePost)
}
