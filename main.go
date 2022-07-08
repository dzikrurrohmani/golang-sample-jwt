package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

func main() {
	routerEngine := gin.Default()
	routerGroup := routerEngine.Group("/api")

	routerGroup.GET("/customer", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		if err := ctx.ShouldBindHeader(&authHeader); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid",
			})
			return
		}

		if authHeader.AuthorizationHeader == "123456" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "customer",
			})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
	})

	routerGroup.GET("/product", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		if err := ctx.ShouldBindHeader(&authHeader); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid",
			})
			return
		}

		if authHeader.AuthorizationHeader == "123456" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "product",
			})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
	})

	err := routerEngine.Run(":8888")
	if err != nil {
		panic(err)
	}
}


func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.Request.URL.Path == "/api/auth/login5" {
			ctx.Next()
		} else {
			h := AuthHeader{}
			if err := ctx.ShouldBindHeader(&h); err != nil {
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"message": err.Error(),
				})
			}

			if h.AuthorizationHeader == "ini_token" {
				ctx.Next()
			} else {
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"message": "token invalid",
				})
				ctx.Abort()
			}
		}
	}
}

