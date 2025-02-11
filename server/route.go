package server

import (
	"github.com/ElvinEga/socialmedia/server/handlers"
	"gorm.io/gorm"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App, db *gorm.DB) {
	// Public routes
	app.Post("/auth/register", handlers.Register)
	app.Post("/auth/login", handlers.Login)
	app.Get("/auth/google", handlers.GoogleLogin)
	app.Get("/auth/google/callback", handlers.GoogleCallback)
	app.Get("/auth/github", handlers.GitHubLogin)
	app.Get("/auth/github/callback", handlers.GitHubCallback)
	app.Get("/verify-email/:token", handlers.VerifyEmail)

	// Protected routes
	app.Group("/users", handlers.JWTMiddleware(db), func(userGroup *fiber.Group) {
		userGroup.Put("/me", handlers.UpdateProfile)
		userGroup.Put("/password", handlers.ChangePassword)
		userGroup.Post("/logout", handlers.Logout)
	})

	// Posts routes
	app.Group("/posts", handlers.JWTMiddleware(db), func(postGroup *fiber.Group) {
		postGroup.Post("", handlers.CreatePost)
		postGroup.Get("", handlers.GetTimeline)
		postGroup.Get("/:id", handlers.GetPost)
		postGroup.Delete("/:id", handlers.DeletePost)
	})
}
