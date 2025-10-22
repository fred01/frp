// Copyright 2020 guylewin, guy@lewin.co.il
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// JWTAuthSetter implements Setter interface for JWT authentication on client side
type JWTAuthSetter struct {
	additionalAuthScopes []v1.AuthScope
	token                string
}

// NewJWTAuthSetter creates a new JWT authentication setter
func NewJWTAuthSetter(additionalAuthScopes []v1.AuthScope, token string) *JWTAuthSetter {
	return &JWTAuthSetter{
		additionalAuthScopes: additionalAuthScopes,
		token:                token,
	}
}

func (auth *JWTAuthSetter) SetLogin(loginMsg *msg.Login) error {
	loginMsg.PrivilegeKey = auth.token
	return nil
}

func (auth *JWTAuthSetter) SetPing(pingMsg *msg.Ping) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	pingMsg.PrivilegeKey = auth.token
	return nil
}

func (auth *JWTAuthSetter) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	newWorkConnMsg.PrivilegeKey = auth.token
	return nil
}

// publicKeyCache stores public keys with expiry time
type publicKeyCache struct {
	mu    sync.RWMutex
	cache map[string]*cachedPublicKey
}

type cachedPublicKey struct {
	key        interface{}
	expireTime time.Time
}

var pkCache = &publicKeyCache{
	cache: make(map[string]*cachedPublicKey),
}

// get retrieves a public key from cache if it exists and hasn't expired
func (c *publicKeyCache) get(source string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.cache[source]
	if !exists {
		return nil, false
	}

	if time.Now().After(cached.expireTime) {
		return nil, false
	}

	return cached.key, true
}

// set stores a public key in cache with 1 hour expiry
func (c *publicKeyCache) set(source string, key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[source] = &cachedPublicKey{
		key:        key,
		expireTime: time.Now().Add(1 * time.Hour),
	}
}

// JWTAuthVerifier implements Verifier interface for JWT authentication on server side
type JWTAuthVerifier struct {
	additionalAuthScopes []v1.AuthScope
	publicKeySource      string
}

// NewJWTAuthVerifier creates a new JWT authentication verifier
func NewJWTAuthVerifier(additionalAuthScopes []v1.AuthScope, publicKeySource string) *JWTAuthVerifier {
	return &JWTAuthVerifier{
		additionalAuthScopes: additionalAuthScopes,
		publicKeySource:      publicKeySource,
	}
}

// getPublicKey retrieves the public key based on the configured source
func (auth *JWTAuthVerifier) getPublicKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	// Check cache first
	if cachedKey, found := pkCache.get(auth.publicKeySource); found {
		return cachedKey, nil
	}

	var publicKey interface{}
	var err error

	// Parse the source and load the appropriate public key
	if strings.HasPrefix(auth.publicKeySource, "file:") {
		// Load from file
		filePath := strings.TrimPrefix(auth.publicKeySource, "file:")
		publicKey, err = loadPublicKeyFromFile(filePath)
	} else if strings.HasPrefix(auth.publicKeySource, "url:") {
		// Load from URL (JWKS)
		jwksURL := strings.TrimPrefix(auth.publicKeySource, "url:")
		publicKey, err = loadPublicKeyFromJWKS(ctx, jwksURL, token)
	} else if strings.HasPrefix(auth.publicKeySource, "jwt-field:") {
		// Load from JWT field (e.g., issuer)
		fieldName := strings.TrimPrefix(auth.publicKeySource, "jwt-field:")
		publicKey, err = loadPublicKeyFromJWTField(ctx, token, fieldName)
	} else {
		return nil, fmt.Errorf("invalid public key source format: %s", auth.publicKeySource)
	}

	if err != nil {
		return nil, err
	}

	// Cache the public key
	pkCache.set(auth.publicKeySource, publicKey)
	return publicKey, nil
}

// loadPublicKeyFromFile loads a public key from a PEM file
func loadPublicKeyFromFile(filePath string) (interface{}, error) {
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return parsePublicKey(keyData)
}

// parsePublicKey parses a PEM-encoded public key
func parsePublicKey(keyData []byte) (interface{}, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Try to parse as PKIX public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}

	// Try to parse as RSA public key
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return rsaPub, nil
	}

	return nil, fmt.Errorf("failed to parse public key")
}

// loadPublicKeyFromJWKS loads a public key from a JWKS URL
func loadPublicKeyFromJWKS(ctx context.Context, jwksURL string, token *jwt.Token) (interface{}, error) {
	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Fetch JWKS
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	// Parse JWKS
	var jwks struct {
		Keys []struct {
			Kid string   `json:"kid"`
			Kty string   `json:"kty"`
			Use string   `json:"use"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Find the key with matching kid
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			if key.Kty == "RSA" {
				// Try to get public key from x5c if available
				if len(key.X5c) > 0 {
					certData := []byte("-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----")
					return parsePublicKeyFromCert(certData)
				}
				// Otherwise construct from n and e
				return constructRSAPublicKey(key.N, key.E)
			}
		}
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// parsePublicKeyFromCert extracts public key from certificate
func parsePublicKeyFromCert(certData []byte) (interface{}, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.PublicKey, nil
}

// constructRSAPublicKey constructs an RSA public key from n and e values
func constructRSAPublicKey(n, e string) (*rsa.PublicKey, error) {
	// This would require base64 decoding and big.Int construction
	// For simplicity, we'll return an error for now
	return nil, fmt.Errorf("constructing RSA key from n/e not yet implemented")
}

// loadPublicKeyFromJWTField loads public key from a JWT field (like issuer)
func loadPublicKeyFromJWTField(ctx context.Context, token *jwt.Token, fieldName string) (interface{}, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	fieldValue, ok := claims[fieldName].(string)
	if !ok {
		return nil, fmt.Errorf("field %s not found in token or not a string", fieldName)
	}

	// If the field value is a URL, try to fetch JWKS from there
	if strings.HasPrefix(fieldValue, "http://") || strings.HasPrefix(fieldValue, "https://") {
		jwksURL := fieldValue
		if !strings.HasSuffix(jwksURL, "/.well-known/jwks.json") {
			jwksURL = strings.TrimSuffix(jwksURL, "/") + "/.well-known/jwks.json"
		}
		return loadPublicKeyFromJWKS(ctx, jwksURL, token)
	}

	return nil, fmt.Errorf("unsupported field value format: %s", fieldValue)
}

func (auth *JWTAuthVerifier) VerifyLogin(m *msg.Login) error {
	return auth.verifyToken(m.PrivilegeKey)
}

func (auth *JWTAuthVerifier) VerifyPing(m *msg.Ping) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	return auth.verifyToken(m.PrivilegeKey)
}

func (auth *JWTAuthVerifier) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	return auth.verifyToken(m.PrivilegeKey)
}

func (auth *JWTAuthVerifier) verifyToken(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("JWT token is empty")
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}

		return auth.getPublicKey(context.Background(), token)
	})

	if err != nil {
		return fmt.Errorf("failed to parse JWT token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid JWT token")
	}

	return nil
}
