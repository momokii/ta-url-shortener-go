package controllers

import (
	"net/http"
	"ta-url-shortener-go/utils"

	"github.com/gin-gonic/gin"
)

func template(c *gin.Context) {

	db := utils.DBSelect(c)

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": db,
	})
}

func CheckSelf(c *gin.Context) {

	db := utils.DBSelect(c)

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": db,
	})
}
