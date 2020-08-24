package cognito

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCognito_Authorize(t *testing.T) {
	encodedPEM := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx5bgIZ4l2OglogZmYPwj
oJTRbsgq0BEN7hAxU4YnYHKdXB9tAx6TsGIXRbq3TxIXZdMv5W5EhSMZYQ1rvLuW
3FkYme29zQTkFrA/TlYn8Oh0L/iF8B4IJ0vYjX5465bzj2+N00nK9e2ozvPv5su2
IIpy+VCdMfESyu3H83xej60jwxdN67EvtE7kF2xfbNjIyQ+IYaIo0e/FIWrlv13w
FB9V1+nZ13sNdVRiJO9GU/GHdT+6soVKY7moKrxOfZZn9ZG63a//ZfXDwJhEXEHU
QVX4TlPf3qnEQBsdw7fUhC7WIlZa2Dd/La7TywttnZOOIi0hqLWqYg/rl/t+XBQW
mQIDAQAB
-----END PUBLIC KEY-----
`
	block, _ := pem.Decode([]byte(encodedPEM))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pem := pub.(*rsa.PublicKey)

	type args struct {
		headers map[string]string
	}
	type fields struct {
		ClientId   string
		Iss        string
		PublicKeys PublicKeys
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantCode  int
		wantToken *jwt.Token
	}{
		{
			name: "Valid",
			fields: fields{
				ClientId: "xxxxxxxxxxxxexample",
				Iss:      "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example",
				PublicKeys: PublicKeys{
					"abcdefghijklmnopqrsexample=": PublicKey{
						Alg: "RS256",
						Kid: "abcdefghijklmnopqrsexample=",
						Kty: "RSA",
						N:   "x5bgIZ4l2OglogZmYPwjoJTRbsgq0BEN7hAxU4YnYHKdXB9tAx6TsGIXRbq3TxIXZdMv5W5EhSMZYQ1rvLuW3FkYme29zQTkFrA_TlYn8Oh0L_iF8B4IJ0vYjX5465bzj2-N00nK9e2ozvPv5su2IIpy-VCdMfESyu3H83xej60jwxdN67EvtE7kF2xfbNjIyQ-IYaIo0e_FIWrlv13wFB9V1-nZ13sNdVRiJO9GU_GHdT-6soVKY7moKrxOfZZn9ZG63a__ZfXDwJhEXEHUQVX4TlPf3qnEQBsdw7fUhC7WIlZa2Dd_La7TywttnZOOIi0hqLWqYg_rl_t-XBQWmQ",
						E:   "AQAB",
						Use: "sig",
						PEM: pem,
					},
				},
			},
			args: args{
				headers: map[string]string{
					"Authorization": "Bearer eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC0yX2V4YW1wbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYW5heWEiLCJleHAiOjIyMjkzNTE0MjUsImdpdmVuX25hbWUiOiJBbmF5YSIsImlhdCI6MTUwMDAwOTQwMCwiZW1haWwiOiJhbmF5YUBleGFtcGxlLmNvbSJ9.AY5I76r10CEkUuA6KbYnWOmMXq6h_YbqjfNYB3s5JG75iBA6EcliNVMpdKqxmBEk6cczfKj9RdCQ6ndu2MK4wvqP1OH8OuJdREq9Isx6HASFpSRmpTjNV3CGPhV-kqzSh9To7m4_geB9lMpLPRbJl_In62oM8FD17RfD3ufjQ26rhZKWFn_DdpoRUEaSISSiKZOFXiIyhmJgsMUjub9UyemBl1w3X9Eq8S0ZUbauIE4qdGcix_KHsLIiaDt7XqROvXKxmLFLTZJJelJ92VyiCCKfrNnzMPdelgktWVMi3GOYaP2KEYdtgFvd6kGp5c3S0BEydsbaulhkXQaSKwJZkg",
				},
			},
			wantCode: 200,
			wantToken: &jwt.Token{
				Raw: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC0yX2V4YW1wbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYW5heWEiLCJleHAiOjIyMjkzNTE0MjUsImdpdmVuX25hbWUiOiJBbmF5YSIsImlhdCI6MTUwMDAwOTQwMCwiZW1haWwiOiJhbmF5YUBleGFtcGxlLmNvbSJ9.AY5I76r10CEkUuA6KbYnWOmMXq6h_YbqjfNYB3s5JG75iBA6EcliNVMpdKqxmBEk6cczfKj9RdCQ6ndu2MK4wvqP1OH8OuJdREq9Isx6HASFpSRmpTjNV3CGPhV-kqzSh9To7m4_geB9lMpLPRbJl_In62oM8FD17RfD3ufjQ26rhZKWFn_DdpoRUEaSISSiKZOFXiIyhmJgsMUjub9UyemBl1w3X9Eq8S0ZUbauIE4qdGcix_KHsLIiaDt7XqROvXKxmLFLTZJJelJ92VyiCCKfrNnzMPdelgktWVMi3GOYaP2KEYdtgFvd6kGp5c3S0BEydsbaulhkXQaSKwJZkg",
				Header: map[string]interface{}{
					"alg": "RS256",
					"kid": "abcdefghijklmnopqrsexample=",
				},
				Claims: jwt.MapClaims{
					"sub":              "aaaaaaaa-bbbb-cccc-dddd-example",
					"aud":              "xxxxxxxxxxxxexample",
					"email_verified":   true,
					"token_use":        "id",
					"auth_time":        float64(1500009400),
					"iss":              "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example",
					"cognito:username": "anaya",
					"exp":              float64(2229351425),
					"given_name":       "Anaya",
					"iat":              float64(1500009400),
					"email":            "anaya@example.com",
				},
				Signature: "AY5I76r10CEkUuA6KbYnWOmMXq6h_YbqjfNYB3s5JG75iBA6EcliNVMpdKqxmBEk6cczfKj9RdCQ6ndu2MK4wvqP1OH8OuJdREq9Isx6HASFpSRmpTjNV3CGPhV-kqzSh9To7m4_geB9lMpLPRbJl_In62oM8FD17RfD3ufjQ26rhZKWFn_DdpoRUEaSISSiKZOFXiIyhmJgsMUjub9UyemBl1w3X9Eq8S0ZUbauIE4qdGcix_KHsLIiaDt7XqROvXKxmLFLTZJJelJ92VyiCCKfrNnzMPdelgktWVMi3GOYaP2KEYdtgFvd6kGp5c3S0BEydsbaulhkXQaSKwJZkg",
				Method: &jwt.SigningMethodRSA{
					Name: "RS256",
					Hash: crypto.Hash(5),
				},
				Valid: true,
			},
		},
		{
			name: "Invalid Auth Header",
			fields: fields{
				ClientId: "xxxxxxxxxxxxexample",
				Iss:      "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example",
				PublicKeys: PublicKeys{
					"abcdefghijklmnopqrsexample=": PublicKey{
						Alg: "RS256",
						Kid: "abcdefghijklmnopqrsexample=",
						Kty: "RSA",
						N:   "x5bgIZ4l2OglogZmYPwjoJTRbsgq0BEN7hAxU4YnYHKdXB9tAx6TsGIXRbq3TxIXZdMv5W5EhSMZYQ1rvLuW3FkYme29zQTkFrA_TlYn8Oh0L_iF8B4IJ0vYjX5465bzj2-N00nK9e2ozvPv5su2IIpy-VCdMfESyu3H83xej60jwxdN67EvtE7kF2xfbNjIyQ-IYaIo0e_FIWrlv13wFB9V1-nZ13sNdVRiJO9GU_GHdT-6soVKY7moKrxOfZZn9ZG63a__ZfXDwJhEXEHUQVX4TlPf3qnEQBsdw7fUhC7WIlZa2Dd_La7TywttnZOOIi0hqLWqYg_rl_t-XBQWmQ",
						E:   "AQAB",
						Use: "sig",
						PEM: pem,
					},
				},
			},
			args: args{
				headers: map[string]string{
					"Authorization": "Bearer",
				},
			},
			wantCode:  http.StatusForbidden,
			wantToken: nil,
		},
		{
			name: "Invalid token",
			fields: fields{
				ClientId: "xxxxxxxxxxxxexample",
				Iss:      "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example",
				PublicKeys: PublicKeys{
					"abcdefghijklmnopqrsexample=": PublicKey{
						Alg: "RS256",
						Kid: "abcdefghijklmnopqrsexample=",
						Kty: "RSA",
						N:   "x5bgIZ4l2OglogZmYPwjoJTRbsgq0BEN7hAxU4YnYHKdXB9tAx6TsGIXRbq3TxIXZdMv5W5EhSMZYQ1rvLuW3FkYme29zQTkFrA_TlYn8Oh0L_iF8B4IJ0vYjX5465bzj2-N00nK9e2ozvPv5su2IIpy-VCdMfESyu3H83xej60jwxdN67EvtE7kF2xfbNjIyQ-IYaIo0e_FIWrlv13wFB9V1-nZ13sNdVRiJO9GU_GHdT-6soVKY7moKrxOfZZn9ZG63a__ZfXDwJhEXEHUQVX4TlPf3qnEQBsdw7fUhC7WIlZa2Dd_La7TywttnZOOIi0hqLWqYg_rl_t-XBQWmQ",
						E:   "AQAB",
						Use: "sig",
						PEM: pem,
					},
				},
			},
			args: args{
				headers: map[string]string{
					"Authorization": "Bearer eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZ1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC0yX2V4YW1wbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYW5heWEiLCJleHAiOjIyMjkzNTE0MjUsImdpdmVuX25hbWUiOiJBbmF5YSIsImlhdCI6MTUwMDAwOTQwMCwiZW1haWwiOiJhbmF5YUBleGFtcGxlLmNvbSJ9.AY5I76r10CEkUuA6KbYnWOmMXq6h_YbqjfNYB3s5JG75iBA6EcliNVMpdKqxmBEk6cczfKj9RdCQ6ndu2MK4wvqP1OH8OuJdREq9Isx6HASFpSRmpTjNV3CGPhV-kqzSh9To7m4_geB9lMpLPRbJl_In62oM8FD17RfD3ufjQ26rhZKWFn_DdpoRUEaSISSiKZOFXiIyhmJgsMUjub9UyemBl1w3X9Eq8S0ZUbauIE4qdGcix_KHsLIiaDt7XqROvXKxmLFLTZJJelJ92VyiCCKfrNnzMPdelgktWVMi3GOYaP2KEYdtgFvd6kGp5c3S0BEydsbaulhkXQaSKwJZkg",
				},
			},
			wantCode:  http.StatusForbidden,
			wantToken: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cog := &Cognito{
				ClientId:   tt.fields.ClientId,
				Iss:        tt.fields.Iss,
				PublicKeys: tt.fields.PublicKeys,
			}
			r := gin.New()
			r.GET("/user", cog.Authorize(), func(c *gin.Context) {
				token, ok := c.Get("token")
				if tt.wantToken != nil {
					assert.True(t, ok)
					assert.Equal(t, tt.wantToken, token.(*jwt.Token))
				} else {
					assert.False(t, ok)
				}
				c.String(http.StatusOK, "ok")
			})
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/user", nil)
			for k, v := range tt.args.headers {
				req.Header.Set(k, v)
			}
			r.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

func Test_tokenFromAuthHeader(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{
		{
			name: "Valid",
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Authorization": []string{"Bearer abc"},
					},
				},
			},
			want:    "abc",
			wantErr: nil,
		},
		{
			name: "Invalid - not bearer",
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Authorization": []string{"invalid abc"},
					},
				},
			},
			want:    "",
			wantErr: errors.New("invalid Authorization header format"),
		},
		{
			name: "Invalid format",
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Authorization": []string{"Bearer part1 part2"},
					},
				},
			},
			want:    "",
			wantErr: errors.New("invalid Authorization header format"),
		},
		{
			name: "Invalid format",
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Authorization": []string{"Bearer"},
					},
				},
			},
			want:    "",
			wantErr: errors.New("invalid Authorization header format"),
		},
		{
			name: "Invalid - empty",
			args: args{
				r: &http.Request{
					Header: http.Header{},
				},
			},
			want:    "",
			wantErr: errors.New("no token"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenFromAuthHeader(tt.args.r)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
