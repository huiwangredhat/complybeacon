package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock JWKS server for testing
func setupMockJWKSServer(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	// Convert RSA public key to JWK format
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	jwk := JWK{
		Kid: "test-key-id",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   n,
		E:   e,
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := OIDCDiscovery{
			Issuer:  "https://kubernetes.default.svc",
			JWKSURI: "http://" + r.Host + "/openid/v1/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discovery)
	})

	// JWKS endpoint
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	return httptest.NewServer(mux)
}

func TestJWTAuthMiddlewareWithJWKS(t *testing.T) {
	// Generate test RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Set up mock JWKS server
	jwksServer := setupMockJWKSServer(t, privateKey)
	defer jwksServer.Close()

	// Override the OIDC discovery URL for testing
	originalURL := OIDCDiscoveryURL
	defer func() { _ = originalURL }() // Restore after test (though it's a const, this is for documentation)

	// Set up Gin in test mode
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupToken     func() string
		config         JWTAuthConfig
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid token with correct audience",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": "compass-internal",
					"sub": "system:serviceaccount:test:collector",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid token with audience array",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": []string{"compass-internal", "other-audience"},
					"sub": "system:serviceaccount:test:collector",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid token with subject validation",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": "compass-internal",
					"sub": "system:serviceaccount:test:collector",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
				AllowedSubjects: []string{
					"system:serviceaccount:test:collector",
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid token - wrong subject",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": "compass-internal",
					"sub": "system:serviceaccount:test:unauthorized",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
				AllowedSubjects: []string{
					"system:serviceaccount:test:collector",
				},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "subject validation failed",
		},
		{
			name: "invalid token - wrong audience",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": "wrong-audience",
					"sub": "system:serviceaccount:test:collector",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "audience validation failed",
		},
		{
			name: "invalid token - expired",
			setupToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"aud": "compass-internal",
					"sub": "system:serviceaccount:test:collector",
					"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
					"iat": time.Now().Add(-2 * time.Hour).Unix(),
				})
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid token",
		},
		{
			name: "missing authorization header",
			setupToken: func() string {
				return ""
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing authorization header",
		},
		{
			name: "invalid authorization header format",
			setupToken: func() string {
				return "InvalidFormat"
			},
			config: JWTAuthConfig{
				ExpectedAudience: "compass-internal",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid authorization header format",
		},
	}

	// Pre-populate global cache with mock JWKS before running tests
	// This must happen before any middleware is created
	mockCache := &jwksCache{
		keys:       make(map[string]*rsa.PublicKey),
		httpClient: jwksServer.Client(),
	}

	// Fetch JWKS from mock server
	resp, err := mockCache.httpClient.Get(jwksServer.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var discovery OIDCDiscovery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&discovery))

	resp, err = mockCache.httpClient.Get(discovery.JWKSURI)
	require.NoError(t, err)
	defer resp.Body.Close()

	var jwks JWKS
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))

	for _, key := range jwks.Keys {
		pubKey, err := parseRSAPublicKey(key)
		require.NoError(t, err)
		mockCache.keys[key.Kid] = pubKey
	}
	mockCache.expiration = time.Now().Add(time.Hour)

	// Inject mock cache before creating middleware
	setJWKSCacheForTesting(mockCache)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create router with middleware
			r := gin.New()
			r.Use(JWTAuthMiddleware(tt.config))

			// Add a test endpoint
			r.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			tokenString := tt.setupToken()
			if tokenString != "" {
				if tokenString == "InvalidFormat" {
					req.Header.Set("Authorization", tokenString)
				} else {
					req.Header.Set("Authorization", "Bearer "+tokenString)
				}
			}

			// Perform request
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name             string
		claims           jwt.MapClaims
		expectedAudience string
		wantErr          bool
	}{
		{
			name: "matching string audience",
			claims: jwt.MapClaims{
				"aud": "compass-internal",
			},
			expectedAudience: "compass-internal",
			wantErr:          false,
		},
		{
			name: "matching audience in array",
			claims: jwt.MapClaims{
				"aud": []interface{}{"compass-internal", "other"},
			},
			expectedAudience: "compass-internal",
			wantErr:          false,
		},
		{
			name: "non-matching string audience",
			claims: jwt.MapClaims{
				"aud": "wrong-audience",
			},
			expectedAudience: "compass-internal",
			wantErr:          true,
		},
		{
			name: "non-matching audience array",
			claims: jwt.MapClaims{
				"aud": []interface{}{"wrong1", "wrong2"},
			},
			expectedAudience: "compass-internal",
			wantErr:          true,
		},
		{
			name:             "missing audience claim",
			claims:           jwt.MapClaims{},
			expectedAudience: "compass-internal",
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAudience(tt.claims, tt.expectedAudience)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSubject(t *testing.T) {
	tests := []struct {
		name            string
		subject         string
		allowedSubjects []string
		wantErr         bool
	}{
		{
			name:    "matching subject",
			subject: "system:serviceaccount:test:collector",
			allowedSubjects: []string{
				"system:serviceaccount:test:collector",
			},
			wantErr: false,
		},
		{
			name:    "matching subject in list",
			subject: "system:serviceaccount:test:collector",
			allowedSubjects: []string{
				"system:serviceaccount:test:other",
				"system:serviceaccount:test:collector",
			},
			wantErr: false,
		},
		{
			name:    "non-matching subject",
			subject: "system:serviceaccount:test:unauthorized",
			allowedSubjects: []string{
				"system:serviceaccount:test:collector",
			},
			wantErr: true,
		},
		{
			name:            "missing subject",
			subject:         "",
			allowedSubjects: []string{"system:serviceaccount:test:collector"},
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubject(tt.subject, tt.allowedSubjects)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert to JWK format
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	tests := []struct {
		name    string
		jwk     JWK
		wantErr bool
	}{
		{
			name: "valid RSA key",
			jwk: JWK{
				Kid: "test-key",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   n,
				E:   e,
			},
			wantErr: false,
		},
		{
			name: "invalid modulus encoding",
			jwk: JWK{
				Kid: "test-key",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   "invalid!!!base64",
				E:   e,
			},
			wantErr: true,
		},
		{
			name: "invalid exponent encoding",
			jwk: JWK{
				Kid: "test-key",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   n,
				E:   "invalid!!!base64",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := parseRSAPublicKey(tt.jwk)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, pubKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pubKey)
				assert.Equal(t, privateKey.N, pubKey.N)
				assert.Equal(t, privateKey.E, pubKey.E)
			}
		})
	}
}
