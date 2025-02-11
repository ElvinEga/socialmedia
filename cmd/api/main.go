package main

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ElvinEga/socialmedia/internal/database"
	"github.com/ElvinEga/socialmedia/server"
)

func main() {
	// Load environment variables
	if err := godotenv.Load("../env/.env"); err != nil {
		panic("Failed to load environment variables")
	}

	// Initialize database
	db, err := gorm.Open(sqlite.Open("socialmedia.db"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}

	// Migrate database schema
	db.AutoMigrate(
		&database.User{},
		&database.Post{},
		&database.Like{},
		&database.Comment{},
		&database.EmailVerificationToken{},
		&database.RevokedToken{},
	)

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		ServerHeader: "Fiber-SocialMedia",
	})

	// Middleware
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, Cookie",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	// Routes
	server.SetupRoutes(app, db)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	app.Listen(":" + port)
}
