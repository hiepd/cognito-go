package cognito

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func (cog *Cognito) Authorize(c *gin.Context) {
	tokenHeader, err := tokenFromAuthHeader(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "invalid Authorization header"})
		return
	}
	token, err := cog.VerifyToken(tokenHeader)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "invalid token"})
		return
	}
	c.Set("token", token)
	c.Set("username", token.Claims.(jwt.MapClaims)["username"])
	c.Next()
}

func tokenFromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no token")
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid Authorization header format")
	}

	return parts[1], nil
}
