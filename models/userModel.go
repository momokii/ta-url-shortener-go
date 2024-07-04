package models

import "time"

type UserModelRes struct {
	Id       string `json:"id" bson:"_id"`
	Username string `json:"username" bson:"username"`
	Name     string `json:"name" bson:"name"`
	Role     int    `json:"role" bson:"role"`
	IsActive bool   `json:"is_active" bson:"is_active"`
}

type UserModel struct {
	UserModelRes `bson:",inline"` // make can inline scanning with mongo
	Password     string           `json:"password" bson:"password"`
	CreatedAt    time.Time        `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at" bson:"updated_at"`
}
