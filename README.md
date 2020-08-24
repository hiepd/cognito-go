# cognito-go [![build](https://travis-ci.com/hiepd/cognito-go.svg?branch=master)](https://travis-ci.com/github/hiepd/cognito-go)  [![Go Report Card](https://goreportcard.com/badge/github.com/hiepd/cognito-go)](https://goreportcard.com/report/github.com/hiepd/cognito-go)  [![Coverage Status](https://coveralls.io/repos/github/hiepd/cognito-go/badge.svg?branch=master)](https://coveralls.io/github/hiepd/cognito-go?branch=master)
JWT Authentication with AWS Cognito in Go + Gin Middleware

# Usage
## Single

```
import "github.com/hiepd/cognito-go"

c, _ := cognito.NewCognito("ap-southeast-2", "cognito-app", "xxx")
token, err := c.VerifyToken("abc")
```

## Gin Middleware

```
import (
  "github.com/hiepd/cognito-go"
  "github.com/gin-gonic/gin"
)

c, _ := cognito.NewCognito("ap-southeast-2", "cognito-app", "xxx")
r := gin.New()
r.GET("/protected", c.Authorize(), protectedEndpoint)
```
