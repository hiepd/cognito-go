package cognito

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCognito_VerifyToken(t *testing.T) {
	encodedPEM1 := `
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
	block1, _ := pem.Decode([]byte(encodedPEM1))
	pub1, _ := x509.ParsePKIXPublicKey(block1.Bytes)
	pem1 := pub1.(*rsa.PublicKey)

	encodedPEM2 := `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtVKUtcx/n9rt5afY/2WF
NvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb+h0qup5j
znOvOr+Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIv
kvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr/EPLMW4wHvH0zZCuRMARIJmmqiM
y3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU/BUhrc2sIgfnvZ03koCQRoZ
mWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw+7V+P7jwrQRFfQV
XwIDAQAB
-----END RSA PUBLIC KEY-----
`
	block2, _ := pem.Decode([]byte(encodedPEM2))
	pub2, _ := x509.ParsePKIXPublicKey(block2.Bytes)
	pem2 := pub2.(*rsa.PublicKey)

	type fields struct {
		ClientId   string
		Iss        string
		PublicKeys PublicKeys
	}
	type args struct {
		tokenStr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *jwt.Token
		wantErr error
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
						PEM: pem1,
					},
					"fgjhlkhjlkhexample=": PublicKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "fgjhlkhjlkhexample=",
						Kty: "RSA",
						N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
						Use: "sig",
						PEM: pem2,
					},
				},
			},
			args: args{
				tokenStr: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC0yX2V4YW1wbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYW5heWEiLCJleHAiOjIyMjkzNTE0MjUsImdpdmVuX25hbWUiOiJBbmF5YSIsImlhdCI6MTUwMDAwOTQwMCwiZW1haWwiOiJhbmF5YUBleGFtcGxlLmNvbSJ9.AY5I76r10CEkUuA6KbYnWOmMXq6h_YbqjfNYB3s5JG75iBA6EcliNVMpdKqxmBEk6cczfKj9RdCQ6ndu2MK4wvqP1OH8OuJdREq9Isx6HASFpSRmpTjNV3CGPhV-kqzSh9To7m4_geB9lMpLPRbJl_In62oM8FD17RfD3ufjQ26rhZKWFn_DdpoRUEaSISSiKZOFXiIyhmJgsMUjub9UyemBl1w3X9Eq8S0ZUbauIE4qdGcix_KHsLIiaDt7XqROvXKxmLFLTZJJelJ92VyiCCKfrNnzMPdelgktWVMi3GOYaP2KEYdtgFvd6kGp5c3S0BEydsbaulhkXQaSKwJZkg",
			},
			want: &jwt.Token{
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
			wantErr: nil,
		},
		{
			name: "Invalid audience claim",
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
						PEM: pem1,
					},
					"fgjhlkhjlkhexample=": PublicKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "fgjhlkhjlkhexample=",
						Kty: "RSA",
						N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
						Use: "sig",
						PEM: pem2,
					},
				},
			},
			args: args{
				tokenStr: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHhleGFtcGxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTAwMDA5NDAwLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20vYXAtc291dGhlYXN0LTJfZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MjIyOTM1MTQyNSwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.sEwx-Oo414fbeQj5B6B7BaTP-Bn6UEyl56lmca-fMJvQYCLEoSK8T-CjMqgEqcS5xW0OMZrex0Gr7VBHZjffd11XcOMVQfijGmFnQOh6Ms-kb5bcMIAS9CT6IWsPcwCMOJF0FzxxBJlQ4_xx0VaB-kGfEOaMzex4AtJaJ7phW73LNSHzjW2B3FfBfME2jDYhOCh_Jr-9NyO_maIXSCCH4sdSB9f4zLz51LGeFlMwrbxeLfLELviBIqVIgheVSDQnkPteKvMU8zrjWSw4O546m5IrWpYdFma_97wyqXxuHC8wwt3sRiTlWh_eDr3jb8PgVuhwcMXHiecRKLU-lIIO5A",
			},
			want: &jwt.Token{
				Raw: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHhleGFtcGxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTAwMDA5NDAwLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20vYXAtc291dGhlYXN0LTJfZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MjIyOTM1MTQyNSwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.sEwx-Oo414fbeQj5B6B7BaTP-Bn6UEyl56lmca-fMJvQYCLEoSK8T-CjMqgEqcS5xW0OMZrex0Gr7VBHZjffd11XcOMVQfijGmFnQOh6Ms-kb5bcMIAS9CT6IWsPcwCMOJF0FzxxBJlQ4_xx0VaB-kGfEOaMzex4AtJaJ7phW73LNSHzjW2B3FfBfME2jDYhOCh_Jr-9NyO_maIXSCCH4sdSB9f4zLz51LGeFlMwrbxeLfLELviBIqVIgheVSDQnkPteKvMU8zrjWSw4O546m5IrWpYdFma_97wyqXxuHC8wwt3sRiTlWh_eDr3jb8PgVuhwcMXHiecRKLU-lIIO5A",
				Header: map[string]interface{}{
					"alg": "RS256",
					"kid": "abcdefghijklmnopqrsexample=",
				},
				Claims: jwt.MapClaims{
					"sub":              "aaaaaaaa-bbbb-cccc-dddd-example",
					"aud":              "xxxxxxxxxxxexample",
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
				Signature: "sEwx-Oo414fbeQj5B6B7BaTP-Bn6UEyl56lmca-fMJvQYCLEoSK8T-CjMqgEqcS5xW0OMZrex0Gr7VBHZjffd11XcOMVQfijGmFnQOh6Ms-kb5bcMIAS9CT6IWsPcwCMOJF0FzxxBJlQ4_xx0VaB-kGfEOaMzex4AtJaJ7phW73LNSHzjW2B3FfBfME2jDYhOCh_Jr-9NyO_maIXSCCH4sdSB9f4zLz51LGeFlMwrbxeLfLELviBIqVIgheVSDQnkPteKvMU8zrjWSw4O546m5IrWpYdFma_97wyqXxuHC8wwt3sRiTlWh_eDr3jb8PgVuhwcMXHiecRKLU-lIIO5A",
				Method: &jwt.SigningMethodRSA{
					Name: "RS256",
					Hash: crypto.Hash(5),
				},
				Valid: true,
			},
			wantErr: errors.New("audience is invalid"),
		},
		{
			name: "Invalid kid",
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
						PEM: pem1,
					},
					"fgjhlkhjlkhexample=": PublicKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "fgjhlkhjlkhexample=",
						Kty: "RSA",
						N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
						Use: "sig",
						PEM: pem2,
					},
				},
			},
			args: args{
				tokenStr: "eyJraWQiOiJiY2RlZmdoaWprbG1ub3BxcnNleGFtcGxlPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC1fZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MjIyOTM1MTQyNSwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.FWBK3XqrwCThxrCzn50go6YX2NmX5_cDDxwHWUcBr9cDDHb3eH_95g6uzBWWTiePHwc_zzcjtrOfto_Tjc9wFPCZMDl-Gf40LhML_as8HoTnEdWWOYrdsPT3LZIGajaaylFcWJEjK4Y9ZZEMheWXCFwuLxuzl24AKN4VgGxP91Jo5mcvEONIjZF1Yc0-yziZ5rCOUeyYnSlm6zIePxmkl6JE64Bcx58Ff2K4pVxOHPRgmCcrXkqlgXmAs-KrjKtEXvUXoB3rDP_FTa4zrYotuP9Dv4s9__HK8teJ1zOlDpvN8WP7o6Hw76OCwtojESibHVxodGC2s3wlVfOUAGqwwg",
			},
			want:    nil,
			wantErr: errors.New("invalid kid bcdefghijklmnopqrsexample="),
		},
		{
			name: "Invalid expire",
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
						PEM: pem1,
					},
					"fgjhlkhjlkhexample=": PublicKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "fgjhlkhjlkhexample=",
						Kty: "RSA",
						N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
						Use: "sig",
						PEM: pem2,
					},
				},
			},
			args: args{
				tokenStr: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC1fZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MTUwMDAwOTQwMCwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.mb6a2S_3UM_7vipqCtVbsy6ToJI14BIpR4710ERKuymOYH4Ast08m1143WYozoldX__n23kLDouu0rnHCfXWlXm0c0-6cYK0tdaUbzbjktZlFw-YppeLGByL8Cv3l1sCDyVNB6_JHL_NSOBovJEOrp3uPlRWqD3mYAy190RT6NTY0XZdF5N1IM2WTTQJf7NW8L2Uv5SZPodLYVfWLG9Bfyqiu1TSB74d0V82HIlLIYG8yliQNL5c4P2-xA5jgqatI9zgllC1aNHkd7yrIjgGvE7-pSNwUY5dj_gHqvl4BW3LORAeJRHPTFCok4bCDXtS_Zdz9OzKMGogqCy0q9vUXQ",
			},
			want:    nil,
			wantErr: errors.New("Token is expired"),
		},
		{
			name: "Invalid issuer",
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
						PEM: pem1,
					},
					"fgjhlkhjlkhexample=": PublicKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "fgjhlkhjlkhexample=",
						Kty: "RSA",
						N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
						Use: "sig",
						PEM: pem2,
					},
				},
			},
			args: args{
				tokenStr: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC1fZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MjIyOTM1MTQyNSwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.Z25rogehjcV7kXdGRyPIYoXf8Jg4YwlMShBDhMPiHRrKPTJg4HOGuUhQDaeD8WRo-kXGxM-jL0MHZ1i5qrqkY4YqVT3Ws38u_oDnz12KojFUIzzeenO54gTERpSwLclyfENiHcbn8PsB6wTcNpoHp7q2iTyayTxzeW0N9MV_Ru2528hJhcVuW-ga0mp5fNmyHJ9nr8eawkSgzOMWsYse0l7JQZwl3Lsrqt1DhKGIruyEiu0SpTRF_buIZj-Lo5DODARqMSbv58V4q71ERLohCHFI6YUfHWS4bLGapBNTUJBZjot5rfbZLRBTRRZxDgXdxZ28RxygfJhih-M8bLZUPA",
			},
			want: &jwt.Token{
				Raw: "eyJraWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzZXhhbXBsZT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1leGFtcGxlIiwiYXVkIjoieHh4eHh4eHh4eHh4ZXhhbXBsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUwMDAwOTQwMCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL2FwLXNvdXRoZWFzdC1fZXhhbXBsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJhbmF5YSIsImV4cCI6MjIyOTM1MTQyNSwiZ2l2ZW5fbmFtZSI6IkFuYXlhIiwiaWF0IjoxNTAwMDA5NDAwLCJlbWFpbCI6ImFuYXlhQGV4YW1wbGUuY29tIn0.Z25rogehjcV7kXdGRyPIYoXf8Jg4YwlMShBDhMPiHRrKPTJg4HOGuUhQDaeD8WRo-kXGxM-jL0MHZ1i5qrqkY4YqVT3Ws38u_oDnz12KojFUIzzeenO54gTERpSwLclyfENiHcbn8PsB6wTcNpoHp7q2iTyayTxzeW0N9MV_Ru2528hJhcVuW-ga0mp5fNmyHJ9nr8eawkSgzOMWsYse0l7JQZwl3Lsrqt1DhKGIruyEiu0SpTRF_buIZj-Lo5DODARqMSbv58V4q71ERLohCHFI6YUfHWS4bLGapBNTUJBZjot5rfbZLRBTRRZxDgXdxZ28RxygfJhih-M8bLZUPA",
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
					"iss":              "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-_example",
					"cognito:username": "anaya",
					"exp":              float64(2229351425),
					"given_name":       "Anaya",
					"iat":              float64(1500009400),
					"email":            "anaya@example.com",
				},
				Signature: "Z25rogehjcV7kXdGRyPIYoXf8Jg4YwlMShBDhMPiHRrKPTJg4HOGuUhQDaeD8WRo-kXGxM-jL0MHZ1i5qrqkY4YqVT3Ws38u_oDnz12KojFUIzzeenO54gTERpSwLclyfENiHcbn8PsB6wTcNpoHp7q2iTyayTxzeW0N9MV_Ru2528hJhcVuW-ga0mp5fNmyHJ9nr8eawkSgzOMWsYse0l7JQZwl3Lsrqt1DhKGIruyEiu0SpTRF_buIZj-Lo5DODARqMSbv58V4q71ERLohCHFI6YUfHWS4bLGapBNTUJBZjot5rfbZLRBTRRZxDgXdxZ28RxygfJhih-M8bLZUPA",
				Method: &jwt.SigningMethodRSA{
					Name: "RS256",
					Hash: crypto.Hash(5),
				},
				Valid: true,
			},
			wantErr: errors.New("iss is invalid"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cognito{
				ClientId:   tt.fields.ClientId,
				Iss:        tt.fields.Iss,
				PublicKeys: tt.fields.PublicKeys,
			}
			got, err := c.VerifyToken(tt.args.tokenStr)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCognito_getCert(t *testing.T) {
	encodedPEM1 := `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAok6rvXu95337IxsDXrKz
lIqw/I/zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I+EDgeFLLex
r40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXH
Fq0XuUUgkX/TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp
3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP+yZFb8e0XSNTcQvXaQxAq
mnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz+1NzHssDH/yk6UYFSszhDbWAzy
qwIDAQAB
-----END RSA PUBLIC KEY-----
`
	block1, _ := pem.Decode([]byte(encodedPEM1))
	pub1, _ := x509.ParsePKIXPublicKey(block1.Bytes)
	pem1 := pub1.(*rsa.PublicKey)

	encodedPEM2 := `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtVKUtcx/n9rt5afY/2WF
NvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb+h0qup5j
znOvOr+Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIv
kvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr/EPLMW4wHvH0zZCuRMARIJmmqiM
y3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU/BUhrc2sIgfnvZ03koCQRoZ
mWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw+7V+P7jwrQRFfQV
XwIDAQAB
-----END RSA PUBLIC KEY-----
`
	block2, _ := pem.Decode([]byte(encodedPEM2))
	pub2, _ := x509.ParsePKIXPublicKey(block2.Bytes)
	pem2 := pub2.(*rsa.PublicKey)

	type fields struct {
		ClientId   string
		Iss        string
		PublicKeys PublicKeys
	}
	type args struct {
		token *jwt.Token
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *rsa.PublicKey
		wantErr error
	}{
		{
			name: "Exists KID",
			fields: fields{
				PublicKeys: PublicKeys{
					"kid1": PublicKey{
						Kid: "kid1",
						PEM: pem1,
					},
					"kid2": PublicKey{
						Kid: "kid2",
						PEM: pem2,
					},
				},
			},
			args: args{
				token: &jwt.Token{
					Header: map[string]interface{}{
						"kid": "kid1",
					},
				},
			},
			want:    pem1,
			wantErr: nil,
		},
		{
			name: "Non-existing KID",
			fields: fields{
				PublicKeys: PublicKeys{
					"kid1": PublicKey{
						Kid: "kid1",
						PEM: pem1,
					},
					"kid2": PublicKey{
						Kid: "kid2",
						PEM: pem2,
					},
				},
			},
			args: args{
				token: &jwt.Token{
					Header: map[string]interface{}{
						"kid": "kid3",
					},
				},
			},
			want:    nil,
			wantErr: errors.New("invalid kid kid3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cognito{
				ClientId:   tt.fields.ClientId,
				Iss:        tt.fields.Iss,
				PublicKeys: tt.fields.PublicKeys,
			}
			got, err := c.getCert(tt.args.token)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getPublicKeys(t *testing.T) {
	encodedPEM1 := `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAok6rvXu95337IxsDXrKz
lIqw/I/zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I+EDgeFLLex
r40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXH
Fq0XuUUgkX/TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp
3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP+yZFb8e0XSNTcQvXaQxAq
mnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz+1NzHssDH/yk6UYFSszhDbWAzy
qwIDAQAB
-----END RSA PUBLIC KEY-----
`
	block1, _ := pem.Decode([]byte(encodedPEM1))
	pub1, _ := x509.ParsePKIXPublicKey(block1.Bytes)
	pem1 := pub1.(*rsa.PublicKey)

	encodedPEM2 := `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtVKUtcx/n9rt5afY/2WF
NvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb+h0qup5j
znOvOr+Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIv
kvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr/EPLMW4wHvH0zZCuRMARIJmmqiM
y3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU/BUhrc2sIgfnvZ03koCQRoZ
mWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw+7V+P7jwrQRFfQV
XwIDAQAB
-----END RSA PUBLIC KEY-----
`
	block2, _ := pem.Decode([]byte(encodedPEM2))
	pub2, _ := x509.ParsePKIXPublicKey(block2.Bytes)
	pem2 := pub2.(*rsa.PublicKey)

	type fields struct {
		body string
	}
	tests := []struct {
		name    string
		fields  fields
		want    PublicKeys
		wantErr error
	}{
		{
			name: "Valid",
			fields: fields{
				body: `
{
    "keys": [{
        "alg": "RS256",
        "e": "AQAB",
        "kid": "abcdefghijklmnopqrsexample=",
        "kty": "RSA",
        "n": "ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw",
        "use": "sig"
    }, {
        "alg":
        "RS256",
        "e": "AQAB",
        "kid": "fgjhlkhjlkhexample=",
        "kty": "RSA",
        "n": "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
        "use": "sig"
    }]
}
				`,
			},
			want: PublicKeys{
				"abcdefghijklmnopqrsexample=": PublicKey{
					Alg: "RS256",
					E:   "AQAB",
					Kid: "abcdefghijklmnopqrsexample=",
					Kty: "RSA",
					N:   "ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw",
					Use: "sig",
					PEM: pem1,
				},
				"fgjhlkhjlkhexample=": PublicKey{
					Alg: "RS256",
					E:   "AQAB",
					Kid: "fgjhlkhjlkhexample=",
					Kty: "RSA",
					N:   "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
					Use: "sig",
					PEM: pem2,
				},
			},
			wantErr: nil,
		},
		{
			name: "Invalid e",
			fields: fields{
				body: `
{
    "keys": [{
        "alg": "RS256",
        "e": "AQA",
        "kid": "abcdefghijklmnopqrsexample=",
        "kty": "RSA",
        "n": "ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw",
        "use": "sig"
    }, {
        "alg":
        "RS256",
        "e": "AQAB",
        "kid": "fgjhlkhjlkhexample=",
        "kty": "RSA",
        "n": "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
        "use": "sig"
    }]
}
				`,
			},
			want:    nil,
			wantErr: errors.New("E AQA is invalid"),
		},
		{
			name: "Invalid json",
			fields: fields{
				body: `
{
    "keys: [{
        "alg": "RS256",
        "e": "AQAB",
        "kid": "abcdefghijklmnopqrsexample=",
        "kty": "RSA",
        "n": "ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw",
        "use": "sig"
    }, {
        "alg":
        "RS256",
        "e": "AQAB",
        "kid": "fgjhlkhjlkhexample=",
        "kty": "RSA",
        "n": "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
        "use": "sig"
    }]
}
				`,
			},
			want:    nil,
			wantErr: errors.New("invalid character '\\n' in string literal"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.fields.body))
			}))
			got, err := getPublicKeys(ts.URL)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parsePEM(t *testing.T) {
	type fields struct {
		Kty string
		E   string
		N   string
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr error
	}{
		{
			name: "Valid",
			fields: fields{
				Kty: "RSA",
				E:   "AQAB",
				N:   "33TqqLR3eeUmDtHS89qF3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA04DDnEFGAf-kDQiNSe2ZtqC7bnIc8-KSG_qOGQIVaay4Ucr6ovDkykO5Hxn7OU7sJp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwFwnxCsU5-UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUEf0YN3_Q0auBkdbDR_ES2PbgKTJdkjc_rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1WSw",
			},
			want: `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA33TqqLR3eeUmDtHS89qF
3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA
04DDnEFGAf+kDQiNSe2ZtqC7bnIc8+KSG/qOGQIVaay4Ucr6ovDkykO5Hxn7OU7s
Jp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwF
wnxCsU5+UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUE
f0YN3/Q0auBkdbDR/ES2PbgKTJdkjc/rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1W
SwIDAQAB
-----END RSA PUBLIC KEY-----
`,
			wantErr: nil,
		},
		{
			name: "Invalid E",
			fields: fields{
				Kty: "RSA",
				E:   "AQA",
				N:   "33TqqLR3eeUmDtHS89qF3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA04DDnEFGAf-kDQiNSe2ZtqC7bnIc8-KSG_qOGQIVaay4Ucr6ovDkykO5Hxn7OU7sJp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwFwnxCsU5-UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUEf0YN3_Q0auBkdbDR_ES2PbgKTJdkjc_rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1WSw",
			},
			want:    "",
			wantErr: errors.New("E AQA is invalid"),
		},
		{
			name: "Invalid N",
			fields: fields{
				Kty: "RSA",
				E:   "AQAB",
				N:   "33TqqLReeUmDtHS89qF3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA04DDnEFGAf-kDQiNSe2ZtqC7bnIc8-KSG_qOGQIVaay4Ucr6ovDkykO5Hxn7OU7sJp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwFwnxCsU5-UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUEf0YN3_Q0auBkdbDR_ES2PbgKTJdkjc_rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1WSw",
			},
			want:    "",
			wantErr: base64.CorruptInputError(340),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := PublicKey{
				Kty: tt.fields.Kty,
				E:   tt.fields.E,
				N:   tt.fields.N,
			}
			got, err := parsePEM(k)
			assert.Equal(t, tt.wantErr, err)
			if tt.wantErr == nil {
				der, err := x509.MarshalPKIXPublicKey(got)
				require.NoError(t, err)
				block := &pem.Block{
					Type:  "RSA PUBLIC KEY",
					Bytes: der,
				}
				var out bytes.Buffer
				require.NoError(t, pem.Encode(&out, block))
				assert.Equal(t, tt.want, out.String())
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
