package hermes

import (
	"fmt"

	cryptography "github.com/prulloac/hermes-jwt/cryptography"
)

func (j JWT) Sign(key interface{}) ([]byte, error) {
	if j.IsJWS() && j.State() == StateSigned {
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

func (j JWT) Verify(key interface{}) (bool, error) {
	if !j.IsJWS() {
		return false, fmt.Errorf("JWT is not a JWS")
	}
	if j.State() != StateSigned {
		return false, fmt.Errorf("JWT is not signed")
	}
	jwsSigningInput := j.header.ToBase64URL() + "." + j.payload.ToBase64URL()
	switch j.header.Algorithm() {
	case cryptography.AlgorithmHS256, cryptography.AlgorithmHS384, cryptography.AlgorithmHS512:
		return cryptography.HMACVerify(j.Algorithm(), key, jwsSigningInput, j.signature)
	case cryptography.AlgorithmRS256, cryptography.AlgorithmRS384, cryptography.AlgorithmRS512:
		return cryptography.RSAVerify(j.Algorithm(), key, jwsSigningInput, j.signature)
	default:
		return false, fmt.Errorf("unsupported algorithm")
	}
}
