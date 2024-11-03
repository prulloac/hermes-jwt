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

	jwt := JWT{header: header, payload: payload, signature: signature}
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

func TestJWTClaimsSetGetClaim(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe"})
	claim, err := claims.GetClaim("name")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if claim.Name != "name" || claim.Value != "John Doe" {
		t.Errorf("expected claim name: %s, value: %v, got name: %s, value: %v", "name", "John Doe", claim.Name, claim.Value)
	}
}

func TestJWTClaimsSetGetClaimNotFound(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe"})
	_, err := claims.GetClaim("admin")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestJWTClaimsSetAddClaim(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890"})
	claims.AddClaim(Claim{Name: "name", Value: "John Doe"})
	claim, err := claims.GetClaim("name")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if claim.Name != "name" || claim.Value != "John Doe" {
		t.Errorf("expected claim name: %s, value: %v, got name: %s, value: %v", "name", "John Doe", claim.Name, claim.Value)
	}
}

func TestJWTClaimsSetGetClaimValue(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe"})
	value, err := claims.GetClaimValue("name")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if value != "John Doe" {
		t.Errorf("expected value: %v, got: %v", "John Doe", value)
	}
}

func TestJWTClaimsSetSetClaimValue(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890"})
	claims.SetClaimValue("name", "John Doe")
	value, err := claims.GetClaimValue("name")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if value != "John Doe" {
		t.Errorf("expected value: %v, got: %v", "John Doe", value)
	}
}

func TestJWTClaimsSetRemoveClaim(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe"})
	claims.RemoveClaim("name")
	_, err := claims.GetClaim("name")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestJWTClaimsSetGetClaimNames(t *testing.T) {
	claims := NewJWTClaimsSet(map[string]interface{}{"sub": "1234567890", "name": "John Doe"})
	names := claims.GetClaimNames()
	expected := []string{"sub", "name"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("expected name: %s, got: %s", expected[i], name)
		}
	}
}
