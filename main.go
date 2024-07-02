package main

import (
	"fmt"
	"os"
	"ta-url-shortener-go/controllers"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/routes"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload" // auto load .env
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		c.Next()
	}
}

func main() {

	db.InitPostgres()
	db.InitMongoDB()

	is_production := os.Getenv("PRODUCTION")
	if is_production == "true" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	r.Use(CORS())

	// * routing
	apiV1 := r.Group("/api/v1")

	routes.SetupAuthRoutes(apiV1.Group("/auth"))
	// routes.SetupUserRoutes(r.Group("/user"))
	apiV1.GET("/:short_link", controllers.GetLinkMain)

	// * start
	port := "8888" // os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}

	fmt.Println("Server running on port:", port)

	err := r.Run(":" + port)
	if err != nil {
		fmt.Println(err)
	}

}
