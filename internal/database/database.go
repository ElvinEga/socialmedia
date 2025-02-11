package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID              uuid.UUID      `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	Username        string         `gorm:"unique;not null" json:"username"`
	Email           string         `gorm:"unique;not null" json:"email"`
	Password        string         `gorm:"not null" json:"-"`
	Bio             string         `json:"bio,omitempty"`
	ProfilePicture  string         `json:"profile_picture,omitempty"`
	Followings      []User         `gorm:"many2many:user_followers;" json:"-"`
	Followers       []User         `gorm:"many2many:user_followers;" json:"-"`
	CreatedAt       time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
	EmailVerified   bool           `gorm:"default:false" json:"email_verified"`
	PasswordVersion int            `gorm:"default:1" json:"password_version"`
}

type Post struct {
	gorm.Model
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	UserID    uuid.UUID      `gorm:"not null" json:"-"`
	Content   string         `gorm:"not null" json:"content"`
	User      User           `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Likes     []Like         `gorm:"foreignKey:PostID" json:"likes,omitempty"`
	Comments  []Comment      `gorm:"foreignKey:PostID" json:"comments,omitempty"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Like struct {
	gorm.Model
	UserID uuid.UUID `gorm:"not null" json:"-"`
	PostID uuid.UUID `gorm:"not null" json:"-"`
}

type Comment struct {
	gorm.Model
	UserID  uuid.UUID `gorm:"not null" json:"-"`
	PostID  uuid.UUID `gorm:"not null" json:"-"`
	Content string    `gorm:"not null" json:"content"`
}

type EmailVerificationToken struct {
	gorm.Model
	Token     string    `gorm:"unique;size:255;not null" json:"token"`
	UserID    uuid.UUID `gorm:"not null" json:"user_id"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
}

type RevokedToken struct {
	gorm.Model
	JTI    string    `gorm:"unique;size:36;not null" json:"jti"`
	UserID uuid.UUID `gorm:"not null" json:"user_id"`
}
