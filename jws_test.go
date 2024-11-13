package hermes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseJWS(t *testing.T) {
	// Test with a valid JWT string
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
	jwt, err := ParseJWS(validJWT)
	assert.NoError(t, err)
	assert.Equal(t, "HS256", jwt.Algorithm())
	jwt.Verify([]byte("secret"))
	assert.Equal(t, SignatureVerified, jwt.state)

	// Test with an empty JWT string
	_, err = ParseJWS("")
	assert.Error(t, err)

	// Test with an invalid JWT string (wrong number of parts)
	_, err = ParseJWS("invalid.jwt.string")
	assert.Error(t, err)

	// Test with a JWT string with an invalid base64 header
	invalidBase64JWT := "invalid_base64.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	_, err = ParseJWS(invalidBase64JWT)
	assert.Error(t, err)
}

func TestVerifySignature(t *testing.T) {
	// Test with a valid HMAC signature
	j := JWT{
		header:    JoseHeader{"alg": "HS256"},
		signature: []byte("signature"),
	}
	err := j.Verify([]byte("key"))
	assert.NoError(t, err)
	assert.Equal(t, SignatureVerified, j.state)

	// Test with a valid RSA signature
	j = JWT{
		header:    JoseHeader{"alg": "RS256"},
		signature: []byte("signature"),
	}
	err = j.Verify([]byte("key"))
	assert.NoError(t, err)
	assert.Equal(t, SignatureVerified, j.state)

	// Test with an unsupported algorithm
	j = JWT{
		header:    JoseHeader{"alg": "unsupported"},
		signature: []byte("signature"),
	}
	err = j.Verify([]byte("key"))
	assert.Error(t, err)

	j = JWT{
		header:    JoseHeader{"alg": "HS256"},
		signature: []byte("signature"),
	}
	err = j.Verify([]byte("key"))
	assert.Error(t, err)
	assert.Equal(t, InvalidJWT, j.state)
}
