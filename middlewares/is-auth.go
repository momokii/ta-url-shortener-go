package middlewares

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strconv"
	"strings"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func IsAuth(c *gin.Context) {
	db_select := utils.DBSelect(c)

	var (
		token string
		user  models.UserModel
	)

	token = c.GetHeader("Authorization")
	if token == "" {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		c.Abort()
		return
	}

	Header := strings.Split(token, " ")
	tokenHeader := Header[0]
	if tokenHeader != "Bearer" {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth With Bearer Token")
		c.Abort()
		return
	}

	tokenHeader = Header[1]
	if tokenHeader != "" {
		utils.ThrowErr(c, http.StatusUnauthorized, "Token not Valid")
		c.Abort()
		return
	}

	// * decode token
	decode_token, err := jwt.Parse(tokenHeader, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		utils.ThrowErr(c, http.StatusUnauthorized, err.Error())
		c.Abort()
		return
	}
	userId := decode_token.Claims.(jwt.MapClaims)["userId"].(string)

	if db_select == "sql" {
		// * check token
		row := db.DB.QueryRow("SELECT id, username, password, name, role, is_active, created_at, updated_at FROM users WHERE id = ?", userId)

		var id int

		err := row.Scan(&id, &user.Username, &user.Password, &user.Name, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

		user.Id = strconv.Itoa(id)

	} else {

		// mongodb disini
		// var id int

		err := db.Collections.UserCollection.FindOne(context.TODO(), bson.M{"_id": userId}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

		// Convert _id to string if needed
		// if _, ok := user.Id.(int); ok {
		// 	user.Id = strconv.Itoa(user.Id.(int))
		// }

	}

	c.Set("userId", userId)
	c.Set("user", user)
	c.Set("role", user.Role)
	c.Next()
}
