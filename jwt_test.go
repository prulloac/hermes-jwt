package hermes

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestJWTToString(t *testing.T) {
	header := JoseHeader{"alg": "HS256", "typ": "JWT"}
	payload := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe", "admin": true})
	signature := []byte("signature")

	jwt := JWT{Header: header, Payload: payload, Signature: signature}
	expected := header.ToBase64URL() + "." + payload.ToBase64URL() + "." + base64.URLEncoding.EncodeToString(signature)

	if jwt.String() != expected {
		t.Errorf("expected %s, got %s", expected, jwt.String())
	}
}

func TestJoseHeaderToBase64URL(t *testing.T) {
	header := JoseHeader{"alg": "HS256", "typ": "JWT"}
	expected, _ := json.Marshal(header)
	expectedStr := base64.URLEncoding.EncodeToString(expected)

	if header.ToBase64URL() != expectedStr {
		t.Errorf("expected %s, got %s", expectedStr, header.ToBase64URL())
	}
}

func TestJoseHeaderAlgorithm(t *testing.T) {
	header := JoseHeader{"alg": "HS256"}
	expected := "HS256"

	if header.Algorithm() != expected {
		t.Errorf("expected %s, got %s", expected, header.Algorithm())
	}
}

func TestJoseHeaderParameter(t *testing.T) {
	header := JoseHeader{"alg": "HS256", "typ": "JWT"}
	expected := "JWT"

	if header.Parameter("typ") != expected {
		t.Errorf("expected %s, got %s", expected, header.Parameter("typ"))
	}
}

func TestClaimsToBase64URL(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe", "admin": true})
	expected, _ := json.Marshal(claims)
	expectedStr := base64.URLEncoding.EncodeToString(expected)

	if claims.ToBase64URL() != expectedStr {
		t.Errorf("expected %s, got %s", expectedStr, claims.ToBase64URL())
	}
}
