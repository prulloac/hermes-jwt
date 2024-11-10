package cryptography

import (
	"crypto/hmac"
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

// HMACSign signs a JWT using HMAC algorithm and the provided key and returns the signature.
func HMACSign(algorithm string, jwsSigningInput string, key interface{}) ([]byte, error) {
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

func RSASign(algorithm string, jwsSigningInput string, key interface{}) ([]byte, error) {
	if algorithm == AlgorithmRS256 {
		// RSA using SHA-256
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmRS384 {
		// RSA using SHA-384
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmRS512 {
		// RSA using SHA-512
		return nil, fmt.Errorf("unsupported algorithm")
	} else {
		return nil, fmt.Errorf("unsupported algorithm")
	}
}

func ECDSASign(algorithm string, jwsSigningInput string, key interface{}) ([]byte, error) {
	if algorithm == AlgorithmES256 {
		// ECDSA using SHA-256
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmES384 {
		// ECDSA using SHA-384
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmES512 {
		// ECDSA using SHA-512
		return nil, fmt.Errorf("unsupported algorithm")
	} else {
		return nil, fmt.Errorf("unsupported algorithm")
	}
}

func RSAPSSSign(algorithm string, jwsSigningInput string, key interface{}) ([]byte, error) {
	if algorithm == AlgorithmPS256 {
		// RSASSA-PSS using SHA-256
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmPS384 {
		// RSASSA-PSS using SHA-384
		return nil, fmt.Errorf("unsupported algorithm")
	} else if algorithm == AlgorithmPS512 {
		// RSASSA-PSS using SHA-512
		return nil, fmt.Errorf("unsupported algorithm")
	} else {
		return nil, fmt.Errorf("unsupported algorithm")
	}
}
