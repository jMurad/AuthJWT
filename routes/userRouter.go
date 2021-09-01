package routes

import (
	controller "testJunior/controllers"

	"github.com/gin-gonic/gin"
)

//UserRoutes function
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/signup", controller.SignUp)
	incomingRoutes.POST("/users/login", controller.Login)
	incomingRoutes.POST("/users/refresh", controller.Refresh)
}