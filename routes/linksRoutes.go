package routes

import (
	"ta-url-shortener-go/controllers"
	"ta-url-shortener-go/middlewares"

	"github.com/gin-gonic/gin"
)

func SetupLinkRoutes(router *gin.RouterGroup) {
	router.GET("/", middlewares.IsAuth, middlewares.IsAdmin, controllers.GetAllLinks)

	router.GET("/self", middlewares.IsAuth, controllers.GetLinkSelf)

	router.GET("/:id", middlewares.IsAuth, controllers.GetOneLink)

	router.POST("/", middlewares.IsAuth, controllers.CreateLink)

	router.PATCH("/", middlewares.IsAuth, controllers.EditLink)

	router.DELETE("/", middlewares.IsAuth, controllers.DeleteLink)
}
