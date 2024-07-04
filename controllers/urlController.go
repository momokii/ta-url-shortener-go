package controllers

import (
	"context"
	"database/sql"
	"math/rand"
	"net/http"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// * ------------------ FUNCTION
func GenerateRandomString(length int) string {
	const char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var randomStr = make([]byte, length)

	// Seed the random number generator to get different results each time
	rand.Seed(time.Now().UnixNano())

	for i := range randomStr {
		randomStr[i] = char[rand.Intn(len(char))]
	}

	return string(randomStr)
}

// * ------------------ CONTROLLER
func GetLinkMain(c *gin.Context) {
	var linkRes models.LinkModel

	db_select := utils.DBSelect(c)

	short_link := c.Params.ByName("short_link")

	if db_select == "sql" {
		row := db.DB.QueryRow("SELECT long_link, short_link FROM urls WHERE short_link = $1", short_link)

		err := row.Scan(&linkRes.LongLink, &linkRes.ShortLink)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusNotFound, "short link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

		_, err = db.DB.Exec("UPDATE urls SET total_visited = total_visited + 1, last_visited = NOW() WHERE short_link = $1", short_link)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}

	} else {
		err := db.Collections.LinkCollection.FindOne(context.TODO(), bson.M{"short_link": short_link}).Decode(&linkRes)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "short link Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

		_, err = db.Collections.LinkCollection.UpdateOne(context.TODO(), bson.M{"short_link": short_link}, bson.M{"$set": bson.M{"total_visited": linkRes.TotalVisited + 1, "last_visited": time.Now()}})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "short link found",
		"data": gin.H{
			"long_url":  linkRes.LongLink,
			"short_url": linkRes.ShortLink,
		},
	})
}

func GetAllLinks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func GetLinkSelf(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func GetOneLink(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func CreateLink(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func EditLink(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func DeleteLink(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}
