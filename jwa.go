// Reference: https://datatracker.ietf.org/doc/html/rfc7518
package hermes

func (j JWT) Algorithm() string {
	return j.header.Algorithm()
}

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

func (j JWT) IsJWS() bool {
	return IsJWS(j.header.Algorithm())
}

func IsJWS(s string) bool {
	switch s {
	case AlgorithmHS256,
		AlgorithmHS384,
		AlgorithmHS512,
		AlgorithmRS256,
		AlgorithmRS384,
		AlgorithmRS512,
		AlgorithmES256,
		AlgorithmES384,
		AlgorithmES512,
		AlgorithmPS256,
		AlgorithmPS384,
		AlgorithmPS512,
		AlgorithmNone:
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
