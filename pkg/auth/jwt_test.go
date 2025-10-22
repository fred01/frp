package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// generateTestKeyPair generates a test RSA key pair
func generateTestKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// savePublicKeyToFile saves a public key to a PEM file
func savePublicKeyToFile(publicKey *rsa.PublicKey, filename string) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return os.WriteFile(filename, pubKeyPEM, 0644)
}

// createTestJWT creates a test JWT token
func createTestJWT(privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	return token.SignedString(privateKey)
}

func TestJWTAuthWithFileSource(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create JWT token
	tokenString, err := createTestJWT(privateKey)
	r.NoError(err)

	// Test client side (setter)
	setter := auth.NewJWTAuthSetter([]v1.AuthScope{}, tokenString)
	loginMsg := &msg.Login{}
	err = setter.SetLogin(loginMsg)
	r.NoError(err)
	r.Equal(tokenString, loginMsg.PrivilegeKey)

	// Test server side (verifier)
	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	err = verifier.VerifyLogin(loginMsg)
	r.NoError(err)
}

func TestJWTAuthWithInvalidToken(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create invalid token (not a valid JWT)
	invalidToken := "invalid.token.string"

	// Test server side (verifier)
	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	loginMsg := &msg.Login{PrivilegeKey: invalidToken}
	err = verifier.VerifyLogin(loginMsg)
	r.Error(err)
	r.Contains(err.Error(), "failed to parse JWT token")
}

func TestJWTAuthWithExpiredToken(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create expired JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	r.NoError(err)

	// Test server side (verifier)
	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	loginMsg := &msg.Login{PrivilegeKey: tokenString}
	err = verifier.VerifyLogin(loginMsg)
	r.Error(err)
}

func TestJWTAuthWithWrongSigningKey(t *testing.T) {
	r := require.New(t)

	// Generate two different key pairs
	privateKey1, err := generateTestKeyPair()
	r.NoError(err)

	privateKey2, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key 2 to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey2.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create JWT token signed with private key 1
	tokenString, err := createTestJWT(privateKey1)
	r.NoError(err)

	// Test server side (verifier) with public key 2
	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	loginMsg := &msg.Login{PrivilegeKey: tokenString}
	err = verifier.VerifyLogin(loginMsg)
	r.Error(err)
}

func TestJWTAuthHeartBeatScope(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create JWT token
	tokenString, err := createTestJWT(privateKey)
	r.NoError(err)

	// Test with HeartBeats scope enabled
	setter := auth.NewJWTAuthSetter([]v1.AuthScope{v1.AuthScopeHeartBeats}, tokenString)
	pingMsg := &msg.Ping{}
	err = setter.SetPing(pingMsg)
	r.NoError(err)
	r.Equal(tokenString, pingMsg.PrivilegeKey)

	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{v1.AuthScopeHeartBeats}, "file:"+pubKeyFile)
	err = verifier.VerifyPing(pingMsg)
	r.NoError(err)

	// Test without HeartBeats scope
	setter2 := auth.NewJWTAuthSetter([]v1.AuthScope{}, tokenString)
	pingMsg2 := &msg.Ping{}
	err = setter2.SetPing(pingMsg2)
	r.NoError(err)
	r.Empty(pingMsg2.PrivilegeKey) // Should not set token

	verifier2 := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	err = verifier2.VerifyPing(pingMsg2)
	r.NoError(err) // Should pass without verification
}

func TestJWTAuthNewWorkConnScope(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create JWT token
	tokenString, err := createTestJWT(privateKey)
	r.NoError(err)

	// Test with NewWorkConns scope enabled
	setter := auth.NewJWTAuthSetter([]v1.AuthScope{v1.AuthScopeNewWorkConns}, tokenString)
	newWorkConnMsg := &msg.NewWorkConn{}
	err = setter.SetNewWorkConn(newWorkConnMsg)
	r.NoError(err)
	r.Equal(tokenString, newWorkConnMsg.PrivilegeKey)

	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{v1.AuthScopeNewWorkConns}, "file:"+pubKeyFile)
	err = verifier.VerifyNewWorkConn(newWorkConnMsg)
	r.NoError(err)

	// Test without NewWorkConns scope
	setter2 := auth.NewJWTAuthSetter([]v1.AuthScope{}, tokenString)
	newWorkConnMsg2 := &msg.NewWorkConn{}
	err = setter2.SetNewWorkConn(newWorkConnMsg2)
	r.NoError(err)
	r.Empty(newWorkConnMsg2.PrivilegeKey) // Should not set token

	verifier2 := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	err = verifier2.VerifyNewWorkConn(newWorkConnMsg2)
	r.NoError(err) // Should pass without verification
}

func TestJWTAuthPublicKeyCaching(t *testing.T) {
	r := require.New(t)

	// Generate test key pair
	privateKey, err := generateTestKeyPair()
	r.NoError(err)

	// Save public key to temp file
	tmpDir := t.TempDir()
	pubKeyFile := filepath.Join(tmpDir, "public.pem")
	err = savePublicKeyToFile(&privateKey.PublicKey, pubKeyFile)
	r.NoError(err)

	// Create JWT token
	tokenString, err := createTestJWT(privateKey)
	r.NoError(err)

	// First verification - should load from file
	verifier := auth.NewJWTAuthVerifier([]v1.AuthScope{}, "file:"+pubKeyFile)
	loginMsg1 := &msg.Login{PrivilegeKey: tokenString}
	err = verifier.VerifyLogin(loginMsg1)
	r.NoError(err)

	// Delete the file
	os.Remove(pubKeyFile)

	// Second verification - should use cached key
	loginMsg2 := &msg.Login{PrivilegeKey: tokenString}
	err = verifier.VerifyLogin(loginMsg2)
	r.NoError(err)
}
