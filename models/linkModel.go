package models

import "time"

type LinkModel struct {
	Id           string    `json:"id" bson:"_id"`
	UserId       string    `json:"user_id" bson:"user_id"`
	ShortLink    string    `json:"short_link" bson:"short_link"`
	LongLink     string    `json:"long_link" bson:"long_link"`
	LastVisited  time.Time `json:"last_visited" bson:"last_visited"`
	TotalVisited int       `json:"total_visited" bson:"total_visited"`
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" bson:"updated_at"`
}

type LinkModelRes struct {
	LinkModel
}
