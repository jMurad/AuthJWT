package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http"
	controller "testJunior/controllers"
	helper "testJunior/helpers"
)

//Промежуточный обработчик, проверящий токены на достоверность
func Authentication(c *gin.Context) {
	tokenAuth, err := helper.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		c.Abort()
		return
	}

	err = controller.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		c.Abort()
		return
	}

	c.Next()
}