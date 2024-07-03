package controllers

import (
	"context"
	"net/http"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// TODO not tested
func CheckSelf(c *gin.Context) {

	var user models.UserModelRes

	userData, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		c.Abort()
		return
	}

	user.Id = userData.(models.UserModel).Id
	user.Username = userData.(models.UserModel).Username
	user.Name = userData.(models.UserModel).Name
	user.Role = userData.(models.UserModel).Role
	user.IsActive = userData.(models.UserModel).IsActive

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "get self data",
		"data":    user,
	})
}

func GetAllUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

// TODO not tested
func GetUserByUsername(c *gin.Context) {
	db_select := utils.DBSelect(c)

	username := c.Params.ByName("username")
	var user models.UserModelRes
	var links []models.LinkModelRes

	if db_select == "sql" {

		err := db.DB.QueryRow("SELECT id, username, name, role, is_active FROM users WHERE username = $1", username).Scan(&user.Id, &user.Username, &user.Name, &user.Role, &user.IsActive)
		if err != nil {
			utils.ThrowErr(c, http.StatusNotFound, "user not found")
			c.Abort()
			return
		}

		linkRows, err := db.DB.Query("SELECT id, long_link, short_link, user_id, last_visited, total_visited, created_at, updated_at FROM urls WHERE user_id = $1", user.Id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}
		defer linkRows.Close()

		for linkRows.Next() {
			var link models.LinkModelRes
			err := linkRows.Scan(&link.Id, &link.LongLink, &link.ShortLink, &link.UserId, &link.LastVisited, &link.TotalVisited, &link.CreatedAt, &link.UpdatedAt)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				c.Abort()
				return
			}
			links = append(links, link)
		}

	} else {

		err := db.Collections.UserCollection.FindOne(c, bson.M{"username": username}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "Username or Password is wrong")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

		linkRows, err := db.Collections.LinkCollection.Find(c, bson.M{"user_id": user.Id})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}

		if err = linkRows.All(context.TODO(), &links); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Info User",
		"data": gin.H{
			"id":        user.Id,
			"username":  user.Username,
			"name":      user.Name,
			"role":      user.Role,
			"is_active": user.IsActive,
			"links":     links,
		},
	})
}

func CreateUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Success create new account",
	})
}

func ChangePassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func ChangeData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func ChangeStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}

func DeleteUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "",
	})
}
