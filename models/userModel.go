package models

import "gorm.io/gorm"

// User represents application user
// @swagger model
// @Success 200 {object} User{ID=uint,CreatedAt=time.Time,UpdatedAt=time.Time,DeletedAt=gorm.DeletedAt}
type User struct {
	gorm.Model   `swaggerignore:"true"`
	Email        string `gorm:"unique"`
	Password     string
	PhotoUrl     *string
	Name         *string
	Surname      *string
	Subscription *string
	Balance      *float64
	RefreshToken *string
}
