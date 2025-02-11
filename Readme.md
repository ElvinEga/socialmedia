# SocialMedia API

https://pkg.go.dev/github.com/yourusername/socialmedia LICENSE
A RESTful API for a social media platform built with Go Fiber, GORM, and SQLite.
Project Structure
Copy

SOCIALMEDIA/
├── cmd/
│ └── api/
│ └── main.go
├── internal/
│ ├── database/
│ │ └── database.go
│ ├── mail/
│ │ └── mail.go
│ └── config/
│ └── config.go
├── server/
│ ├── route.go
│ ├── server.go
│ └── handlers/
│ ├── auth.go
│ ├── user.go
│ └── post.go
├── env/
│ └── .env
├── .gitignore
├── air.toml
├── go.mod
├── go.sum
├── makefile
└── Readme.md

Getting Started
Prerequisites

    Go 1.17+
    SQLite3

Installation

    Clone the repository:

bashCopy

git clone https://github.com/yourusername/socialmedia.git
cd socialmedia

    Install dependencies:

bashCopy

go mod tidy

Environment Setup
Create .env file:
envCopy

JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_secret
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_email_password

Database Setup

    Initialize database:

bashCopy

sqlite3 socialmedia.db

    Run migrations (automatically handled by GORM)

Running the Application
bashCopy

go run cmd/api/main.go

The server will start at http://localhost:8000
API Documentation
Authentication

    POST /auth/register
        Body: { "email": "user@example.com", "password": "securepassword" }
        Creates a new user and sends verification email
    POST /auth/login
        Body: { "email": "user@example.com", "password": "securepassword" }
        Returns JWT access token
    GET /auth/google
        Redirects to Google OAuth2 login
    GET /auth/google/callback
        Handles Google OAuth2 callback
    POST /auth/logout
        Invalidates current session

User Management

    PUT /users/me
        Updates current user's profile
        Body: { "username": "new_username", "bio": "New bio text" }
    PUT /users/password
        Changes current user's password
        Body: { "current_password": "oldpassword", "new_password": "newpassword" }

Posts

    POST /posts
        Creates a new post
        Body: { "content": "Post content" }
    GET /posts
        Retrieves timeline posts
    GET /posts/:id
        Retrieves a single post
    DELETE /posts/:id
        Deletes a post

Security

    JWT authentication with password version check
    Automatic token revocation on logout
    Email verification for local accounts
    HTTPS recommended for production

Contributing

    Fork the repository
    Create a feature branch
    Commit changes and push to your branch
    Create a pull request

Troubleshooting

    Dependency issues: Run go mod tidy
    Database connection errors: Check SQLite file permissions
    Email verification issues: Verify SMTP configuration

License
MIT License - see LICENSE file
.
