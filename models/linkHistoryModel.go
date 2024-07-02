package models

import "time"

type LinkHistoryModel struct {
	Id           string    `json:"id" bson:"_id"`
	UserId       string    `json:"user_id" bson:"user_id"`
	UrlId        string    `json:"url_id" bson:"url_id"`
	ShortLink    string    `json:"short_link" bson:"short_link"`
	LongLink     string    `json:"long_link" bson:"long_link"`
	TotalVisited int       `json:"total_visited" bson:"total_visited"`
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
}
