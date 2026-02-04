package middleware

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// ServiceAccountTokenPath is the default path to Kubernetes service account token
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// ServiceAccountCAPath is the default path to Kubernetes service account CA
	ServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// OIDCDiscoveryURL is the Kubernetes OIDC discovery endpoint
	OIDCDiscoveryURL = "https://kubernetes.default.svc/.well-known/openid-configuration"
	// JWKS cache duration (refresh keys every 1 hour)
	JWKSCacheDuration = 1 * time.Hour
)

// JWTAuthConfig holds the configuration for JWT authentication
type JWTAuthConfig struct {
	// ExpectedAudience is the audience claim that must be present in the JWT
	ExpectedAudience string
	// AllowedSubjects is a list of allowed subject claims (service account names)
	// Format: system:serviceaccount:<namespace>:<serviceaccount-name>
	// If empty, all subjects are allowed
	AllowedSubjects []string
}

// OIDCDiscovery represents the OIDC discovery document
type OIDCDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (RSA)
	Alg string `json:"alg"` // Algorithm
	Use string `json:"use"` // Public key use (sig)
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// jwksCache holds cached JWKS with expiration
type jwksCache struct {
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	expiration time.Time
	httpClient *http.Client
}

var (
	globalJWKSCache *jwksCache
	cacheOnce       sync.Once
)

// getJWKSCache returns the global JWKS cache instance
func getJWKSCache() *jwksCache {
	cacheOnce.Do(func() {
		// Skip initialization if cache is already set (e.g., by tests)
		if globalJWKSCache != nil {
			return
		}

		// Create HTTP client with CA cert for in-cluster communication
		httpClient, err := createK8sHTTPClient()
		if err != nil {
			slog.Error("failed to create HTTP client for JWKS", "error", err)
			// Fallback to default client
			httpClient = &http.Client{Timeout: 10 * time.Second}
		}

		globalJWKSCache = &jwksCache{
			keys:       make(map[string]*rsa.PublicKey),
			httpClient: httpClient,
		}
	})
	return globalJWKSCache
}

// setJWKSCacheForTesting allows tests to inject a mock JWKS cache
// This must be called before any calls to JWTAuthMiddleware
func setJWKSCacheForTesting(cache *jwksCache) {
	globalJWKSCache = cache
}

// fetchJWKS fetches and caches the JWKS from Kubernetes API server
func (c *jwksCache) fetchJWKS() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is still valid
	if time.Now().Before(c.expiration) {
		return nil
	}

	slog.Info("fetching JWKS from Kubernetes API server")

	// Step 1: Fetch OIDC discovery document
	resp, err := c.httpClient.Get(OIDCDiscoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("failed to decode OIDC discovery: %w", err)
	}

	slog.Debug("OIDC discovery", "issuer", discovery.Issuer, "jwks_uri", discovery.JWKSURI)

	// Step 2: Fetch JWKS from the discovered URI with service account token authentication
	// Read service account token for authenticating to the API server
	saToken, err := os.ReadFile(ServiceAccountTokenPath)
	if err != nil {
		slog.Warn("failed to read service account token, trying unauthenticated request", "error", err)
		saToken = nil
	}

	req, err := http.NewRequest("GET", discovery.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	// Add service account token for authentication if available
	if len(saToken) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(saToken))
	}

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Step 3: Parse and cache RSA public keys
	newKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key)
		if err != nil {
			slog.Warn("failed to parse RSA public key", "kid", key.Kid, "error", err)
			continue
		}

		newKeys[key.Kid] = pubKey
		slog.Debug("cached RSA public key", "kid", key.Kid)
	}

	if len(newKeys) == 0 {
		return errors.New("no valid RSA public keys found in JWKS")
	}

	c.keys = newKeys
	c.expiration = time.Now().Add(JWKSCacheDuration)

	slog.Info("JWKS cache updated", "key_count", len(newKeys), "expires_at", c.expiration)

	return nil
}

// getPublicKey returns the RSA public key for the given key ID
func (c *jwksCache) getPublicKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key ID %q not found in JWKS cache", kid)
	}

	return key, nil
}

// parseRSAPublicKey converts a JWK to an RSA public key
func parseRSAPublicKey(key JWK) (*rsa.PublicKey, error) {
	// Decode base64url-encoded modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url-encoded exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// createK8sHTTPClient creates an HTTP client with Kubernetes CA cert for in-cluster communication
func createK8sHTTPClient() (*http.Client, error) {
	// Read CA cert for TLS verification
	caCert, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

// JWTAuthMiddleware creates a Gin middleware that validates bound service account tokens
// with full cryptographic signature verification using JWKS
func JWTAuthMiddleware(config JWTAuthConfig) gin.HandlerFunc {
	cache := getJWKSCache()

	// Pre-fetch JWKS on startup
	if err := cache.fetchJWKS(); err != nil {
		slog.Error("failed to fetch JWKS on startup", "error", err)
	}

	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			slog.Warn("missing authorization header")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			slog.Warn("invalid authorization header format")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		tokenString := parts[1]

		// Refresh JWKS if expired
		if err := cache.fetchJWKS(); err != nil {
			slog.Error("failed to refresh JWKS", "error", err)
		}

		// Parse and validate JWT with signature verification
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get key ID from token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing key ID in token header")
			}

			// Fetch public key from JWKS cache
			return cache.getPublicKey(kid)
		})

		if err != nil {
			slog.Warn("failed to parse and validate token", "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if !token.Valid {
			slog.Warn("token is not valid")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			slog.Warn("invalid token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}

		// Validate audience
		if config.ExpectedAudience != "" {
			if err := validateAudience(claims, config.ExpectedAudience); err != nil {
				slog.Warn("audience validation failed", "error", err)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("audience validation failed: %v", err)})
				return
			}
		}

		// Validate subject (service account) if AllowedSubjects is configured
		if len(config.AllowedSubjects) > 0 {
			sub, _ := claims.GetSubject()
			if err := validateSubject(sub, config.AllowedSubjects); err != nil {
				slog.Warn("subject validation failed", "error", err, "subject", sub)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("subject validation failed: %v", err)})
				return
			}
		}

		// Store claims in context
		c.Set("jwt_claims", claims)

		// Log successful authentication
		sub, _ := claims.GetSubject()
		slog.Debug("jwt authentication successful",
			"subject", sub,
			"audience", claims["aud"],
		)

		c.Next()
	}
}

// validateAudience checks if the expected audience is present in the token's audience claim
func validateAudience(claims jwt.MapClaims, expectedAudience string) error {
	audClaim, ok := claims["aud"]
	if !ok {
		return errors.New("missing audience claim")
	}

	// Audience can be a string or an array of strings
	switch aud := audClaim.(type) {
	case string:
		if aud == expectedAudience {
			return nil
		}
		return fmt.Errorf("expected audience %q, got %q", expectedAudience, aud)
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok && audStr == expectedAudience {
				return nil
			}
		}
		return fmt.Errorf("expected audience %q not found in %v", expectedAudience, aud)
	default:
		return fmt.Errorf("unexpected audience claim type: %T", aud)
	}
}

// validateSubject checks if the subject claim is in the allowed list
func validateSubject(subject string, allowedSubjects []string) error {
	if subject == "" {
		return errors.New("missing subject claim")
	}

	for _, allowed := range allowedSubjects {
		if subject == allowed {
			return nil
		}
	}

	return fmt.Errorf("subject %q not in allowed list", subject)
}
