package routes

import (
	"ta-url-shortener-go/controllers"

	"github.com/gin-gonic/gin"
)

func SetupAuthRoutes(router *gin.RouterGroup) {
	router.POST("/login", controllers.Login)
}
