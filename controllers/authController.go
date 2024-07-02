package controllers

import (
	"database/sql"
	"net/http"
	"os"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *gin.Context) {
	type DataLogin struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	db_select := utils.DBSelect(c)

	var user models.UserModel
	var dataLogin DataLogin

	err := c.ShouldBindJSON(&dataLogin)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, err.Error())
		c.Abort()
		return
	}

	if db_select == "sql" {
		err = db.DB.QueryRow("SELECT id, username, password, is_active FROM users WHERE username = $1", dataLogin.Username).Scan(&user.Id, &user.Username, &user.Password, &user.IsActive)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusUnauthorized, "Username or Password is wrong")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}

	} else {
		err = db.Collections.UserCollection.FindOne(c, bson.M{"username": dataLogin.Username}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "Username or Password is wrong")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			c.Abort()
			return
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(dataLogin.Password))
	if err != nil {
		utils.ThrowErr(c, http.StatusUnauthorized, "Username or Password is wrong")
		c.Abort()
		return
	}

	if !user.IsActive {
		utils.ThrowErr(c, http.StatusUnauthorized, "Your account is not active")
		c.Abort()
		return
	}

	sign := jwt.New(jwt.SigningMethodHS256)
	claims := sign.Claims.(jwt.MapClaims)
	claims["userId"] = user.Id
	claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()

	token, err := sign.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Login Success",
		"data": gin.H{
			"access_token": token,
			"token_type":   "Bearer",
			"expired_time": "30d",
		},
	})
}
