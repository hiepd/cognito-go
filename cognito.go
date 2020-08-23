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
)

var (
	ErrInvalidParam = errors.New("invalid param")
)

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

func NewCognito(region, usePoolId, clientId string) (*Cognito, error) {
	if region == "" || usePoolId == "" {
		return nil, fmt.Errorf("invalid region or use pool id: %w", ErrInvalidParam)
	}
	iss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, usePoolId)
	publicKeys, err := getPublicKeys(iss)
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
		return c.getCert(token)
	})

	if err != nil {
		return nil, err
	}

	// verify claims
	if !token.Claims.(jwt.MapClaims).VerifyAudience(c.ClientId, false) {
		return token, errors.New("audience is invalid")
	}

	if !token.Claims.(jwt.MapClaims).VerifyExpiresAt(time.Now().Unix(), true) {
		return token, errors.New("token expired")
	}

	if !token.Claims.(jwt.MapClaims).VerifyIssuer(c.Iss, true) {
		return token, errors.New("iss is invalid")
	}

	return token, nil
}

func (c *Cognito) getCert(token *jwt.Token) (*rsa.PublicKey, error) {
	if alg := token.Method.Alg(); alg != "RS256" {
		return nil, fmt.Errorf("invalid signing method %s. signing method must be RS256", alg)
	}

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
		if err := key.SetPEM(); err != nil {
			return nil, err
		}
		publicKeys[key.Kid] = key
	}
	return publicKeys, nil
}

func (k *PublicKey) SetPEM() error {
	if k.Kty != "RSA" {
		return fmt.Errorf("KTY %s must be RSA", k.Kty)
	}

	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return err
	}

	e := 0
	if k.E == "AQAB" || k.E == "AAEAAQ" {
		e = 65537
	} else {
		return fmt.Errorf("E %s is invalid", k.E)
	}

	k.PEM = &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: e,
	}
	return nil
}
