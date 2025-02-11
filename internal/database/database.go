type User struct {
	gorm.Model
	ID              uuid.UUID      `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	Username        string         `gorm:"unique" json:"username"`
	Email           string         `gorm:"unique" json:"email"`
	Password        string         `json:"-"`
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

// EmailVerificationToken model
type EmailVerificationToken struct {
	gorm.Model
	Token     string    `gorm:"unique;size:255" json:"token"`
	UserID    uuid.UUID `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RevokedToken model for JWT logout
type RevokedToken struct {
	gorm.Model
	JTI    string    `gorm:"unique;size:36" json:"jti"`
	UserID uuid.UUID `json:"user_id"`
}