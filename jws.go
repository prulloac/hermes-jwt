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
		return cryptography.HMACSign(j.Algorithm(), jwsSigningInput, key.([]byte))
	case cryptography.AlgorithmRS256, cryptography.AlgorithmRS384, cryptography.AlgorithmRS512:
		return cryptography.RSASign(j.Algorithm(), jwsSigningInput, key)
	case cryptography.AlgorithmES256, cryptography.AlgorithmES384, cryptography.AlgorithmES512:
		return cryptography.ECDSASign(j.Algorithm(), jwsSigningInput, key)
	case cryptography.AlgorithmPS256, cryptography.AlgorithmPS384, cryptography.AlgorithmPS512:
		return cryptography.RSAPSSSign(j.Algorithm(), jwsSigningInput, key)
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
	s, err := j.Sign(key)
	if err != nil {
		return false, err
	}
	return string(j.signature) == string(s), nil
}
