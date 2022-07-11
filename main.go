package main

import (
	"golang-sample-jwt/config"
	"golang-sample-jwt/delivery/middleware"
	"golang-sample-jwt/model"
	"golang-sample-jwt/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	routerEngine := gin.Default()
	// routerEngine.Use(AuthTokenMiddleware()) // global middleware
	routerGroup := routerEngine.Group("/api")
	cfg := config.NewConfig()
	tokenService := utils.NewTokenService(cfg.TokenConfig)

	routerGroup.POST("/auth/login", func(c *gin.Context) {
		var user model.Credential
		//authHeader := AuthHeader{}
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {
			// token, err := GenerateToken(user.Username, "admin@enigmacamp.com")
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatus(401)
				return

			}
			c.JSON(200, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(401)
		}
	})

	protectedGroup := routerGroup.Group("/master", middleware.NewTokenValidator(tokenService).RequiredToken())
	protectedGroup.GET("/customer", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "customer",
		})
	})

	protectedGroup.GET("/product", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "product",
		})
	})

	err := routerEngine.Run(":8888")
	if err != nil {
		panic(err)
	}
}
// package main

// import (
// 	"net/http"

// 	"github.com/gin-gonic/gin"
// )

// type AuthHeader struct {
// 	AuthorizationHeader string `header:"Authorization"`
// }

// func main() {
// 	routerEngine := gin.Default()
// 	routerEngine.Use(AuthMiddleware())
// 	routerGroup := routerEngine.Group("/api")

// 	routerGroup.GET("/customer", func(ctx *gin.Context) {
// 		ctx.JSON(http.StatusOK, gin.H{
// 			"message": "customer",
// 		})
// 	})

// 	routerGroup.GET("/product", func(ctx *gin.Context) {
// 		ctx.JSON(http.StatusOK, gin.H{
// 			"message": "product",
// 		})
// 	})

// 	err := routerEngine.Run(":8888")
// 	if err != nil {
// 		panic(err)
// 	}
// }

// func AuthMiddleware() gin.HandlerFunc {
// 	return func(ctx *gin.Context) {
// 		h := AuthHeader{}
// 		if err := ctx.ShouldBindHeader(&h); err != nil {
// 			ctx.JSON(http.StatusUnauthorized, gin.H{
// 				"message": err.Error(),
// 			})
// 		}

// 		if h.AuthorizationHeader == "123456" {
// 			ctx.Next()
// 		} else {
// 			ctx.JSON(http.StatusUnauthorized, gin.H{
// 				"message": "token invalid",
// 			})
// 			ctx.Abort()
// 		}
// 	}
// }

// type AuthHeader struct {
// 	AuthorizationHeader string `header:"Authorization"`
// }

// type Credential struct {
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// }

// var (
// 	ApplicationName  = "Enigma"
// 	JwtSigningMethod = jwt.SigningMethodHS256
// 	JwtSignatureKey  = []byte("3N!GM4")
// )

// type MyClaims struct {
// 	jwt.StandardClaims
// 	Username string `json:"username"`
// 	Email    string `json:"email"`
// }

// func AuthTokenMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		if c.Request.URL.Path == "/api/auth/login" {
// 			c.Next()
// 			fmt.Println("sss")
// 		} else {
// 			h := AuthHeader{}
// 			if err := c.ShouldBindHeader(&h); err != nil {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthrorized",
// 				})
// 				c.Abort()
// 				return
// 			}
// 			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
// 			fmt.Println("token", tokenString)
// 			if tokenString == "" {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthrorized",
// 				})
// 				c.Abort()
// 				return
// 			}
// 			fmt.Println(1)

// 			token, err := ParseToken(tokenString)
// 			if err != nil {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthrorized",
// 				})
// 				c.Abort()
// 				return
// 			}
// 			fmt.Println("token:", token)
// 			if token["iss"] == ApplicationName {
// 				c.Next()
// 			} else {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "token invalid",
// 				})
// 				c.Abort()
// 			}
// 		}

// 	}
// }

// func GenerateToken(userName string, email string) (string, error) {
// 	claims := MyClaims{
// 		StandardClaims: jwt.StandardClaims{
// 			Issuer: ApplicationName,
// 		},
// 		Username: userName,
// 		Email:    email,
// 	}
// 	token := jwt.NewWithClaims(
// 		JwtSigningMethod,
// 		claims,
// 	)
// 	return token.SignedString(JwtSignatureKey)
// }

// func ParseToken(tokenString string) (jwt.MapClaims, error) {
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		method, ok := token.Method.(*jwt.SigningMethodHMAC)
// 		if !ok {
// 			return nil, fmt.Errorf("signing method invalid")
// 		} else if method != JwtSigningMethod {
// 			return nil, fmt.Errorf("signing method invalid")
// 		}
// 		fmt.Println(ok)

// 		return JwtSignatureKey, nil
// 	})
// 	fmt.Println(err)

// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	fmt.Println(ok, token.Valid)
// 	if !ok || !token.Valid {
// 		return nil, err
// 	}
// 	fmt.Println(2)
// 	return claims, nil
// }
