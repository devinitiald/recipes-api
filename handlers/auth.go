package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/devinitiald/recipes-api/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct{}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
type JWTOutput struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

func (handler *AuthHandler) SignInHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if user.Username != "admin" || user.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalud username or password"})
		return
	}
	expirationTime := time.Now().Add(10 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	JWTOutput := JWTOutput{
		Token:   tokenString,
		Expires: expirationTime,
	}
	c.JSON(http.StatusOK, JWTOutput)

	// return func(c *gin.Context) {
	// 	tokenValue := c.GetHeader("Authorization")
	// 	claims := &Claims{}
	// 	tkn, err := jwt.ParseWithClaims(tokenValue, claims,
	// 		func(t *jwt.Token) (interface{}, error) {
	// 			return []byte(os.Getenv("JWT_SECRET")), nil
	// 		})
	// 	if err != nil {
	// 		c.AbortWithStatus(http.StatusUnauthorized)
	// 	}
	// 	if tkn == nil || !tkn.Valid {
	// 		c.AbortWithStatus(http.StatusUnauthorized)
	// 	}
	// 	c.Next()
	// }

}

func (handler *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenValue := c.GetHeader("Authorization")
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenValue, claims,
			func(t *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("JWT_SECRET")), nil
			})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		if tkn == nil || !tkn.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.Next()
	}
}
