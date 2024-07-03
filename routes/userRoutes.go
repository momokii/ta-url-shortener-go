package routes

import (
	"ta-url-shortener-go/controllers"
	"ta-url-shortener-go/middlewares"

	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(router *gin.RouterGroup) {
	router.GET("/", middlewares.IsAuth, middlewares.IsAdmin, controllers.GetAllUser)

	router.GET("/self", middlewares.IsAuth, controllers.CheckSelf)

	router.GET("/:username", middlewares.IsAuth, middlewares.IsAdmin, controllers.GetUserByUsername)

	router.POST("/", middlewares.IsAuth, middlewares.IsAdmin, controllers.CreateUser)

	router.PATCH("/", middlewares.IsAuth, controllers.ChangeData)

	router.PATCH("/password", middlewares.IsAuth, controllers.ChangePassword)

	router.PATCH("/status", middlewares.IsAuth, middlewares.IsAdmin, controllers.ChangeStatus)

	router.DELETE("/delete", middlewares.IsAuth, middlewares.IsAdmin, controllers.DeleteUser)
}
