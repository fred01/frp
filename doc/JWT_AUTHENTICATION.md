# JWT Authentication for FRP

This document describes how to use JWT (JSON Web Token) authentication with FRP.

## Overview

JWT authentication allows clients to authenticate with the FRP server using signed JWT tokens. The server verifies the token's signature using a public key, and the client provides the signed token.

## Features

- **Client Authentication**: Clients provide JWT tokens for authentication
- **Multiple Public Key Sources**: Support for file-based, URL-based (JWKS), and JWT field-based public keys
- **Public Key Caching**: Public keys are cached for 1 hour to improve performance
- **Additional Scopes**: Optional authentication for heartbeats and new work connections
- **Token Expiry Validation**: Automatically validates token expiration

## Configuration

### Server Configuration

The server must specify the JWT authentication method and the public key source:

```toml
[auth]
method = "jwt"

[auth.jwt]
# Public key source options:
# - File: "file:/path/to/public.pem"
# - JWKS URL: "url:https://example.com/.well-known/jwks.json"
# - JWT field: "jwt-field:issuer" (extracts from issuer field in JWT)
publicKeySource = "file:/path/to/public.pem"
```

### Client Configuration

#### Option 1: Direct Token

```toml
[auth]
method = "jwt"

[auth.jwt]
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Option 2: Token from File

```toml
[auth]
method = "jwt"

[auth.jwt.tokenSource]
type = "file"

[auth.jwt.tokenSource.file]
path = "/path/to/token.jwt"
```

### Additional Scopes

To enable JWT authentication for heartbeats and new work connections:

```toml
[auth]
method = "jwt"
additionalScopes = ["HeartBeats", "NewWorkConns"]

[auth.jwt]
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Public Key Sources

### File Source

Load the public key from a PEM file:

```toml
[auth.jwt]
publicKeySource = "file:/etc/frp/public.pem"
```

The public key file should be in PEM format:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

### JWKS URL Source

Load the public key from a JWKS (JSON Web Key Set) endpoint:

```toml
[auth.jwt]
publicKeySource = "url:https://your-auth-provider.com/.well-known/jwks.json"
```

The token must include a `kid` (Key ID) header to identify which key to use from the JWKS.

### JWT Field Source

Extract the JWKS URL from a field in the JWT token (e.g., issuer):

```toml
[auth.jwt]
publicKeySource = "jwt-field:issuer"
```

When the issuer field contains a URL (e.g., `https://accounts.google.com`), the server will automatically append `/.well-known/jwks.json` and fetch the public keys.

## Generating Keys and Tokens

### Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Generate public key
openssl rsa -in private.pem -pubout -out public.pem
```

### Create JWT Token

You can use various tools and libraries to create JWT tokens. Here's an example using the `golang-jwt/jwt` library:

```go
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
)

func main() {
    // Read private key
    privateKeyData, _ := os.ReadFile("private.pem")
    block, _ := pem.Decode(privateKeyData)
    privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
    
    // Create token
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
        "sub": "client-id",
        "exp": time.Now().Add(24 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    })
    
    // Sign token
    tokenString, _ := token.SignedString(privateKey)
    fmt.Println(tokenString)
}
```

## Security Considerations

1. **Private Key Security**: Keep private keys secure and never share them
2. **Token Expiration**: Set appropriate expiration times for tokens
3. **Public Key Rotation**: When rotating keys, ensure smooth transition
4. **HTTPS**: Use HTTPS for JWKS URLs to prevent man-in-the-middle attacks
5. **Token Storage**: Store tokens securely on the client side

## Performance

- Public keys are cached for 1 hour after first use
- Cache reduces the overhead of repeatedly loading keys from files or URLs
- Multiple concurrent requests can share the same cached key

## Supported Algorithms

The JWT implementation currently supports:
- RSA signatures (RS256, RS384, RS512)
- ECDSA signatures (ES256, ES384, ES512)

## Example: Complete Setup

1. Generate keys:
   ```bash
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```

2. Create JWT token (using any JWT library)

3. Configure server (`frps.toml`):
   ```toml
   bindPort = 7000
   
   [auth]
   method = "jwt"
   
   [auth.jwt]
   publicKeySource = "file:/etc/frp/public.pem"
   ```

4. Configure client (`frpc.toml`):
   ```toml
   serverAddr = "your-server.com"
   serverPort = 7000
   
   [auth]
   method = "jwt"
   
   [auth.jwt]
   token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
   ```

5. Start server and client:
   ```bash
   ./frps -c frps.toml
   ./frpc -c frpc.toml
   ```

## Troubleshooting

### "Failed to parse JWT token"
- Verify the token is properly formatted
- Check that the token is not expired
- Ensure the signing algorithm matches

### "Key with kid X not found in JWKS"
- Verify the JWKS URL is accessible
- Check that the token's `kid` header matches a key in the JWKS

### "Invalid public key source format"
- Ensure the `publicKeySource` starts with `file:`, `url:`, or `jwt-field:`
- Check for typos in the source specification

## Migration from Token Authentication

If you're currently using token authentication, you can migrate to JWT:

1. Generate RSA key pair
2. Create a JWT token with appropriate claims
3. Update server configuration to use JWT method
4. Update client configuration to use JWT method
5. Test the connection before deploying widely

Both authentication methods can coexist during migration by running separate server instances.
