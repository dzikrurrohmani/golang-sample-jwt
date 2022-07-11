package middleware

import (
	"fmt"
	"golang-sample-jwt/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type authHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type AuthTokenMiddleware interface {
	RequiredToken() gin.HandlerFunc
}

type authTokenMiddleware struct {
	acctToken utils.Token
}

func (a *authTokenMiddleware) RequiredToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := authHeader{}
		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthrorized",
			})
			c.Abort()
			return
		}
		tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
		fmt.Println("token", tokenString)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthrorized",
			})
			c.Abort()
			return
		}
		fmt.Println(1)

		token, err := a.acctToken.VerifyAccsessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthrorized",
			})
			c.Abort()
			return
		}
		fmt.Println("token:", token)
		if token!= nil {
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "token invalid",
			})
			c.Abort()
		}

	}
}

func NewTokenValidator(acctToken utils.Token) AuthTokenMiddleware {
	return &authTokenMiddleware{acctToken: acctToken}
}
