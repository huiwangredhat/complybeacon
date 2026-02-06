package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
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

		// Create HTTP client with proper TLS validation and optional DNS bypass
		httpClient, err := createK8sHTTPClientWithDNSBypass()
		if err != nil {
			slog.Error("failed to create HTTP client for JWKS", "error", err)
			// Fallback to default client with increased timeout
			httpClient = &http.Client{Timeout: 30 * time.Second}
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
	slog.Info("attempting OIDC discovery", "url", OIDCDiscoveryURL)
	startTime := time.Now()
	resp, err := c.httpClient.Get(OIDCDiscoveryURL)
	elapsed := time.Since(startTime)
	if err != nil {
		slog.Error("OIDC discovery request failed", "elapsed", elapsed, "error", err)
		return fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	slog.Info("OIDC discovery request completed", "elapsed", elapsed, "status", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("failed to decode OIDC discovery: %w", err)
	}

	slog.Debug("OIDC discovery", "issuer", discovery.Issuer, "jwks_uri", discovery.JWKSURI)

	// If DNS bypass is enabled, rewrite external JWKS URI to use internal cluster IP
	// The OIDC discovery returns an external hostname, but we need to use the internal IP
	kubernetesServiceIP := os.Getenv("KUBERNETES_SERVICE_IP")
	jwksURI := discovery.JWKSURI
	if kubernetesServiceIP != "" {
		// Parse the JWKS URI to extract the path
		// Example: https://api.example.com:6443/openid/v1/jwks -> https://10.0.0.1/openid/v1/jwks
		// Note: The Kubernetes Service ClusterIP always uses port 443 (standard HTTPS port)
		if strings.HasPrefix(jwksURI, "https://") && strings.Contains(jwksURI, "/openid/") {
			// Extract the path component after /openid/
			parts := strings.SplitN(jwksURI, "/openid/", 2)
			if len(parts) == 2 {
				originalJWKSURI := jwksURI
				// Always use port 443 for the Kubernetes Service ClusterIP (not 6443)
				jwksURI = fmt.Sprintf("https://%s/openid/%s", kubernetesServiceIP, parts[1])
				slog.Info("rewrote JWKS URI to use internal cluster IP", "original", originalJWKSURI, "rewritten", jwksURI)
			}
		}
	}

	// Step 2: Fetch JWKS from the discovered URI with service account token authentication
	// Read service account token for authenticating to the API server
	saToken, err := os.ReadFile(ServiceAccountTokenPath)
	if err != nil {
		slog.Warn("failed to read service account token, trying unauthenticated request", "error", err)
		saToken = nil
	}

	req, err := http.NewRequest("GET", jwksURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	// Add service account token for authentication if available
	if len(saToken) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(saToken))
		slog.Info("using service account token for JWKS authentication")
	} else {
		slog.Warn("no service account token available, attempting unauthenticated JWKS fetch")
	}

	slog.Info("attempting JWKS fetch", "url", jwksURI)
	startTime = time.Now()
	resp, err = c.httpClient.Do(req)
	elapsed = time.Since(startTime)
	if err != nil {
		slog.Error("JWKS fetch failed", "elapsed", elapsed, "error", err)
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	slog.Info("JWKS fetch completed", "elapsed", elapsed, "status", resp.StatusCode)

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

// createK8sHTTPClientWithDNSBypass creates an HTTP client with proper TLS validation
// and optional DNS bypass for improved reliability in problematic network environments
func createK8sHTTPClientWithDNSBypass() (*http.Client, error) {
	// Read CA cert for TLS verification
	slog.Info("reading Kubernetes CA certificate", "path", ServiceAccountCAPath)
	caCert, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		slog.Error("failed to read CA cert", "path", ServiceAccountCAPath, "error", err)
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	slog.Info("CA certificate read successfully", "size", len(caCert))

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		slog.Error("failed to parse CA certificate as PEM")
		return nil, errors.New("failed to parse CA certificate")
	}
	slog.Info("CA certificate parsed successfully", "cert_count", len(caCertPool.Subjects()))

	// TLS config with proper certificate validation
	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
		// ServerName ensures SNI matches the certificate
		ServerName: "kubernetes.default.svc",
	}
	slog.Info("TLS config created successfully")

	// Custom dialer with optional DNS bypass
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Check if Kubernetes service IP is provided (to bypass DNS)
	kubernetesServiceIP := os.Getenv("KUBERNETES_SERVICE_IP")
	var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	if kubernetesServiceIP != "" {
		// DNS bypass mode: use direct IP address
		slog.Info("DNS bypass enabled - using direct Kubernetes API IP", "kubernetes_ip", kubernetesServiceIP)
		dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Replace kubernetes.default.svc with direct IP
			if strings.Contains(addr, "kubernetes.default.svc") {
				addr = strings.Replace(addr, "kubernetes.default.svc", kubernetesServiceIP, 1)
				slog.Debug("DNS bypass: connecting directly to Kubernetes API", "addr", addr)
			}
			return dialer.DialContext(ctx, network, addr)
		}
	} else {
		// Normal DNS resolution mode
		slog.Info("using standard DNS resolution for Kubernetes API")
		dialContext = dialer.DialContext
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DialContext:           dialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// HTTP/2 is enabled by default (no need to force HTTP/1.1)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// createK8sHTTPClient creates an HTTP client with Kubernetes CA cert for in-cluster communication
// Deprecated: Use createK8sHTTPClientWithDNSBypass instead
func createK8sHTTPClient() (*http.Client, error) {
	// Read CA cert for TLS verification
	slog.Info("reading Kubernetes CA certificate", "path", ServiceAccountCAPath)
	caCert, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		slog.Error("failed to read CA cert", "path", ServiceAccountCAPath, "error", err)
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	slog.Info("CA certificate read successfully", "size", len(caCert))

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		slog.Error("failed to parse CA certificate as PEM")
		return nil, errors.New("failed to parse CA certificate")
	}
	slog.Info("CA certificate parsed successfully", "cert_count", len(caCertPool.Subjects()))

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}
	slog.Info("TLS config created successfully")

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // Increased from 10s to 30s for slower networks
	}, nil
}

// JWTAuthMiddleware creates a Gin middleware that validates bound service account tokens
// with full cryptographic signature verification using JWKS
func JWTAuthMiddleware(config JWTAuthConfig) gin.HandlerFunc {
	cache := getJWKSCache()

	// Pre-fetch JWKS on startup with retry logic
	// Retry up to 3 times with exponential backoff (1s, 2s, 4s)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := cache.fetchJWKS(); err != nil {
			lastErr = err
			slog.Warn("failed to fetch JWKS on startup", "attempt", attempt, "error", err)
			if attempt < 3 {
				backoff := time.Duration(1<<uint(attempt-1)) * time.Second
				slog.Info("retrying JWKS fetch", "backoff", backoff)
				time.Sleep(backoff)
			}
		} else {
			lastErr = nil
			slog.Info("successfully fetched JWKS on startup", "attempt", attempt)
			break
		}
	}
	if lastErr != nil {
		slog.Error("failed to fetch JWKS after retries, will retry on first request", "error", lastErr)
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

		// Signature verification successful
		slog.Info("jwt signature verification successful")

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
			slog.Info("jwt audience validation successful")
		}

		// Validate subject (service account) if AllowedSubjects is configured
		if len(config.AllowedSubjects) > 0 {
			sub, _ := claims.GetSubject()
			if err := validateSubject(sub, config.AllowedSubjects); err != nil {
				slog.Warn("subject validation failed", "error", err, "subject", sub)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("subject validation failed: %v", err)})
				return
			}
			slog.Info("jwt subject validation successful")
		}

		// Store claims in context
		c.Set("jwt_claims", claims)

		// Log successful authentication
		slog.Info("jwt authentication successful")

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
