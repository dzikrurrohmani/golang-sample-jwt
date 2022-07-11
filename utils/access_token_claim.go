package utils

import "github.com/golang-jwt/jwt"

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Email    string `json:"email"`
}
