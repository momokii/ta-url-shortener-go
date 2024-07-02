package db

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Collections struct {
	UserCollection        *mongo.Collection
	LinkCollection        *mongo.Collection
	LinkHistoryCollection *mongo.Collection
}

func InitMongoDB() {
	ctx := context.TODO()

	// * connect to mongo
	clientOptions := options.Client().ApplyURI(os.Getenv("MONGODB_URI"))
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Connect Mongo Error: ", err)
	}

	// * check conn
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Ping Mongo Error: ", err)
	}

	fmt.Println("Connected to MongoDB!")

	// * setup collections and DB name
	db := client.Database(os.Getenv("MONGODB_NAME"))
	Collections.UserCollection = db.Collection("users")
	Collections.LinkCollection = db.Collection("urls")
	Collections.LinkHistoryCollection = db.Collection("urls_history")
}
