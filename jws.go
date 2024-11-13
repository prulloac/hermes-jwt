// Reference: https://tools.ietf.org/html/rfc7515
package hermes

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	cryptography "github.com/prulloac/hermes-jwt/cryptography"
)

func (j JWT) Sign(key interface{}) ([]byte, error) {
	if j.IsJWS() && j.State() != Unsecured {
		return nil, fmt.Errorf("JWT is already signed")
	}
	jwsSigningInput := j.header.ToBase64URL() + "." + j.payload.ToBase64URL()
	switch j.header.Algorithm() {
	case cryptography.AlgorithmHS256, cryptography.AlgorithmHS384, cryptography.AlgorithmHS512:
		return cryptography.HMACSign(j.Algorithm(), key, jwsSigningInput)
	case cryptography.AlgorithmRS256, cryptography.AlgorithmRS384, cryptography.AlgorithmRS512:
		return cryptography.RSASign(j.Algorithm(), key, jwsSigningInput)
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
}

func (j *JWT) Verify(key interface{}) error {
	parts := strings.Split(j.compact, ".")
	if len(parts) != 3 && j.IsJWS() {
		j.state = InvalidJWT
		return fmt.Errorf("JWT is not a valid JWS")
	}
	for _, part := range parts {
		if part == "" {
			j.state = SignatureInvalid
			return fmt.Errorf("invalid JWS")
		}
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			j.state = SignatureInvalid
			return err
		}
	}
	jwsSigningInput := parts[0] + "." + parts[1]
	b := false
	var err error
	switch j.header.Algorithm() {
	case cryptography.AlgorithmHS256, cryptography.AlgorithmHS384, cryptography.AlgorithmHS512:
		b, err = cryptography.HMACVerify(j.Algorithm(), key, jwsSigningInput, j.signature)
	case cryptography.AlgorithmRS256, cryptography.AlgorithmRS384, cryptography.AlgorithmRS512:
		b, err = cryptography.RSAVerify(j.Algorithm(), key, jwsSigningInput, j.signature)
	default:
		j.state = SignatureInvalid
		return fmt.Errorf("unsupported algorithm")
	}
	if err != nil {
		j.state = SignatureInvalid
		return err
	}
	if !b {
		j.state = SignatureInvalid
	} else {
		j.state = SignatureVerified
	}
	return nil
}

func ParseJWS(jwt string) (JWT, error) {
	if jwt == "" {
		return JWT{}, fmt.Errorf("empty JWT")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return JWT{}, fmt.Errorf("invalid JWT")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWT{}, err
	}
	var h JoseHeader = make(map[string]interface{})
	if err := json.Unmarshal(header, &h); err != nil {
		return JWT{}, err
	}
	if !IsJWS(h.Algorithm()) {
		return JWT{}, fmt.Errorf("not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return JWT{}, err
	}
	var claimsMap map[string]interface{} = make(map[string]interface{})
	if err := json.Unmarshal(payload, &claimsMap); err != nil {
		return JWT{}, err
	}
	claims := NewJWTClaimsSet(claimsMap)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return JWT{}, err
	}
	return JWT{
		header:    h,
		payload:   claims,
		compact:   jwt,
		state:     SignatureUnverified,
		signature: signature,
	}, nil
}
