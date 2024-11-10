// Reference: https://datatracker.ietf.org/doc/html/rfc7518
package hermes

import "github.com/prulloac/hermes-jwt/cryptography"

func (j JWT) Algorithm() string {
	return j.header.Algorithm()
}

func (j JWT) IsJWS() bool {
	return IsJWS(j.header.Algorithm())
}

func IsJWS(s string) bool {
	switch s {
	case cryptography.AlgorithmHS256,
		cryptography.AlgorithmHS384,
		cryptography.AlgorithmHS512,
		cryptography.AlgorithmRS256,
		cryptography.AlgorithmRS384,
		cryptography.AlgorithmRS512,
		cryptography.AlgorithmES256,
		cryptography.AlgorithmES384,
		cryptography.AlgorithmES512,
		cryptography.AlgorithmPS256,
		cryptography.AlgorithmPS384,
		cryptography.AlgorithmPS512,
		cryptography.AlgorithmNone:
		return true
	default:
		return false
	}
}

const (
	AlgorithmRSA1_5             = "RSA1_5"
	AlgorithmRSA_OAEP           = "RSA-OAEP"
	AlgorithmRSA_OAEP_256       = "RSA-OAEP-256"
	AlgorithmA128KW             = "A128KW"
	AlgorithmA192KW             = "A192KW"
	AlgorithmA256KW             = "A256KW"
	AlgorithmDir                = "dir"
	AlgorithmECDH_ES            = "ECDH-ES"
	AlgorithmECDH_ES_A128KW     = "ECDH-EA+A128KW"
	AlgorithmECDH_ES_A192KW     = "ECDH-EA+A192KW"
	AlgorithmECDH_ES_A256KW     = "ECDH-EA+A256KW"
	AlgorithmA128GCMKW          = "A128GCMKW"
	AlgorithmA192GCMKW          = "A192GCMKW"
	AlgorithmA256GCMKW          = "A256GCMKW"
	AlgorithmPBES2_HS256_A128KW = "PBES2-HS256+A128KW"
	AlgorithmPBES2_HS384_A192KW = "PBES2-HS384+A192KW"
	AlgorithmPBES2_HS512_A256KW = "PBES2-HS512+A256KW"
)

func (j JWT) IsJWE() bool {
	return IsJWE(j.header.Algorithm())
}

func IsJWE(s string) bool {
	switch s {
	case AlgorithmRSA1_5,
		AlgorithmRSA_OAEP,
		AlgorithmRSA_OAEP_256,
		AlgorithmA128KW,
		AlgorithmA192KW,
		AlgorithmA256KW,
		AlgorithmDir,
		AlgorithmECDH_ES,
		AlgorithmECDH_ES_A128KW,
		AlgorithmECDH_ES_A192KW,
		AlgorithmECDH_ES_A256KW,
		AlgorithmA128GCMKW,
		AlgorithmA192GCMKW,
		AlgorithmA256GCMKW,
		AlgorithmPBES2_HS256_A128KW,
		AlgorithmPBES2_HS384_A192KW,
		AlgorithmPBES2_HS512_A256KW:
		return true
	default:
		return false
	}
}
