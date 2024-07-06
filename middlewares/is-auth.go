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
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	if tokenHeader == "" {
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
		var id int

		// * check token
		err := db.DB.QueryRow("SELECT id, username, password, name, role, is_active, created_at, updated_at FROM users WHERE id = $1", userId).Scan(&id, &user.Username, &user.Password, &user.Name, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)

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

		id, err := primitive.ObjectIDFromHex(userId)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}

		err = db.Collections.UserCollection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

	}

	if !user.IsActive {
		utils.ThrowErr(c, http.StatusUnauthorized, "Your account is not active")
		c.Abort()
		return
	}

	c.Set("userId", userId)
	c.Set("user", user)
	c.Set("role", user.Role)
	c.Next()
}
