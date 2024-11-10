package cryptography

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
)

const (
	AlgorithmHS256 = "HS256"
	AlgorithmHS384 = "HS384"
	AlgorithmHS512 = "HS512"
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"
	AlgorithmES256 = "ES256"
	AlgorithmES384 = "ES384"
	AlgorithmES512 = "ES512"
	AlgorithmPS256 = "PS256"
	AlgorithmPS384 = "PS384"
	AlgorithmPS512 = "PS512"
	AlgorithmNone  = "none"
)

// HMACSign signs a JWT using HMAC algorithm and the provided key, returning the signature bytes.
func HMACSign(algorithm string, key interface{}, jwsSigningInput string) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "recovered from panic, unsupported algorithm received in HMACSign: %v", algorithm)
			os.Exit(1)
		}
	}()
	if keyBytes, ok := key.([]byte); ok {
		var h hash.Hash
		if algorithm == AlgorithmHS256 {
			h = hmac.New(sha256.New, keyBytes)
		} else if algorithm == AlgorithmHS384 {
			h = hmac.New(sha512.New384, keyBytes)
		} else if algorithm == AlgorithmHS512 {
			h = hmac.New(sha512.New, keyBytes)
		}
		if h != nil {
			h.Write([]byte(jwsSigningInput))
			return h.Sum(nil), nil
		}
		return nil, fmt.Errorf("unsupported algorithm")
	}
	return nil, fmt.Errorf("key must be a byte slice")
}

// HMACVerify verifies a JWT signature using HMAC algorithm and the provided key, returning a boolean indicating if the signature is valid.
func HMACVerify(algorithm string, key interface{}, jwsSigningInput string, signature []byte) (bool, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "recovered from panic, unsupported algorithm received in HMACVerify: %v", algorithm)
			os.Exit(1)
		}
	}()
	if keyBytes, ok := key.([]byte); ok {
		var h hash.Hash
		if algorithm == AlgorithmHS256 {
			h = hmac.New(sha256.New, keyBytes)
		} else if algorithm == AlgorithmHS384 {
			h = hmac.New(sha512.New384, keyBytes)
		} else if algorithm == AlgorithmHS512 {
			h = hmac.New(sha512.New, keyBytes)
		}
		if h != nil {
			h.Write([]byte(jwsSigningInput))
			expectedMAC := h.Sum(nil)
			return hmac.Equal(signature, expectedMAC), nil
		}
		return false, fmt.Errorf("unsupported algorithm")
	}
	return false, fmt.Errorf("key must be a byte slice")
}

// RSASign signs a JWT using RSASSA-PKCS1-v1_5 algorithm and the provided private key, returning the signature bytes.
func RSASign(algorithm string, key interface{}, jwsSigningInput string) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "recovered from panic, unsupported algorithm received in HMACSign: %v", algorithm)
			os.Exit(1)
		}
	}()

	if rsaPrivateKey, ok := key.(*rsa.PrivateKey); ok {
		var h crypto.Hash
		if algorithm == AlgorithmRS256 {
			h = crypto.SHA256
		} else if algorithm == AlgorithmRS384 {
			h = crypto.SHA384
		} else if algorithm == AlgorithmRS512 {
			h = crypto.SHA512
		} else {
			return nil, fmt.Errorf("unsupported algorithm")
		}
		if h != 0 {
			i := h.New()
			i.Write([]byte(jwsSigningInput))
			signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, h, i.Sum(nil))
			if err != nil {
				return nil, err
			}
			return signature, nil
		}
	}
	return nil, fmt.Errorf("key must be a *rsa.PrivateKey")
}

// RSAVerify verifies a JWT signature using RSASSA-PKCS1-v1_5 algorithm and the provided public key, returning a boolean indicating if the signature is valid.
func RSAVerify(algorithm string, key interface{}, jwsSigningInput string, signature []byte) (bool, error) {
	if rsaPublicKey, ok := key.(*rsa.PublicKey); ok {
		var h crypto.Hash
		if algorithm == AlgorithmRS256 {
			h = crypto.SHA256
		} else if algorithm == AlgorithmRS384 {
			h = crypto.SHA384
		} else if algorithm == AlgorithmRS512 {
			h = crypto.SHA512
		}
		if h != 0 {
			i := h.New()
			i.Write([]byte(jwsSigningInput))
			return rsa.VerifyPKCS1v15(rsaPublicKey, h, i.Sum(nil), signature) == nil, nil
		}
		return false, fmt.Errorf("unsupported algorithm")
	}
	return false, fmt.Errorf("key must be a *rsa.PublicKey")
}
