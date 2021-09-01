package main

import (
	"github.com/gin-gonic/gin"
	"os"
	helper "testJunior/helpers"
	"testJunior/middleware"
	"testJunior/routes"
)

func main() {
	helper.GetKeysRSA()

	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	routes.UserRoutes(router)

	router.Use(middleware.Authentication)

	// Обработка запросов
	router.GET("/api", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for api-1"})
	})

	router.Run(":" + port)
}