package cognito

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	ErrInvalidParam = errors.New("invalid param")
)

//go:generate mockgen -source=cognito.go -package=cognito -destination=mocks/cognito.go
type Client interface {
	VerifyToken(tokenStr string) (*jwt.Token, error)
	Authorize() gin.HandlerFunc
}

type Cognito struct {
	// AWS App Client ID
	ClientId string

	// AWS Cognito Issuer
	Iss string

	// Map of JWKs from AWS Cognito
	PublicKeys PublicKeys
}

type PublicKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
	PEM *rsa.PublicKey
}

type PublicKeys map[string]PublicKey

func NewCognitoClient(region, usePoolId, clientId string) (Client, error) {
	// validate region and usePoolId, make sure they are present
	if region == "" || usePoolId == "" {
		return nil, fmt.Errorf("invalid region or use pool id: %w", ErrInvalidParam)
	}

	iss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, usePoolId)
	pkUrl := fmt.Sprintf("%s/.well-known/jwks.json", iss)
	publicKeys, err := getPublicKeys(pkUrl)
	if err != nil {
		return nil, err
	}

	return &Cognito{
		ClientId:   clientId,
		Iss:        iss,
		PublicKeys: publicKeys,
	}, nil
}

func (c *Cognito) VerifyToken(tokenStr string) (*jwt.Token, error) {
	// parse token and verify signature
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// validate token signing method
		if alg := token.Method.Alg(); alg != "RS256" {
			return nil, fmt.Errorf("invalid signing method %s. signing method must be RS256", alg)
		}
		return c.getCert(token)
	})

	if err != nil {
		return nil, err
	}

	// verify claims
	// verify audience claim
	if !token.Claims.(jwt.MapClaims).VerifyAudience(c.ClientId, false) {
		return token, errors.New("audience is invalid")
	}

	// verify expire time
	if !token.Claims.(jwt.MapClaims).VerifyExpiresAt(time.Now().Unix(), true) {
		return token, errors.New("token expired")
	}

	// verify issuer
	if !token.Claims.(jwt.MapClaims).VerifyIssuer(c.Iss, true) {
		return token, errors.New("iss is invalid")
	}

	return token, nil
}

func (c *Cognito) getCert(token *jwt.Token) (*rsa.PublicKey, error) {
	kid := token.Header["kid"].(string)
	key, ok := c.PublicKeys[kid]
	if !ok {
		return nil, fmt.Errorf("invalid kid %s", kid)
	}

	return key.PEM, nil
}

func getPublicKeys(iss string) (PublicKeys, error) {
	client := &http.Client{
		Timeout: time.Second * time.Duration(10),
	}
	resp, err := client.Get(iss)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respJson := struct {
		Keys []PublicKey `json:"keys"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return nil, err
	}

	// iterate through list of keys and assign them to key map
	publicKeys := make(map[string]PublicKey)
	for _, key := range respJson.Keys {
		if pem, err := parsePEM(key); err != nil {
			return nil, err
		} else {
			key.PEM = pem
		}
		publicKeys[key.Kid] = key
	}
	return publicKeys, nil
}

func parsePEM(k PublicKey) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("KTY %s must be RSA", k.Kty)
	}

	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}

	e := 0
	if k.E == "AQAB" || k.E == "AAEAAQ" {
		e = 65537
	} else {
		return nil, fmt.Errorf("E %s is invalid", k.E)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: e,
	}, nil
}
