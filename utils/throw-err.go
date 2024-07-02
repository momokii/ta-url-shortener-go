package utils

import "github.com/gin-gonic/gin"

func ThrowErr(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, gin.H{
		"errors":  true,
		"message": message,
	})
}
