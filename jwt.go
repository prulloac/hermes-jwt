// Reference: https://datatracker.ietf.org/doc/html/rfc7519
package hermes

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type StringOrURI string
type NumericDate int64

const JWT_MEDIA_TYPE = "application/jwt"
const JWT_URN = "urn:ietf:params:oauth:token-type:jwt"
const (
	IssuerClaim         = "iss"
	SubjectClaim        = "sub"
	AudienceClaim       = "aud"
	ExpirationTimeClaim = "exp"
	NotBeforeClaim      = "nbf"
	IssuedAtClaim       = "iat"
	JWTIDClaim          = "jti"
)

const (
	TypeHeader        = "typ"
	ContentTypeHeader = "cty"
)

type JWT struct {
	header    JoseHeader
	payload   JWTClaimsSet
	signature []byte
	raw       string
}

type JWTClaimsSet struct {
	Claims []Claim
}

func NewJWTClaimsSet(m map[string]interface{}) JWTClaimsSet {
	claims := make([]Claim, len(m))
	i := 0
	for k, v := range m {
		claims[i] = Claim{Name: k, Value: v}
		i++
	}
	return JWTClaimsSet{Claims: claims}
}

func (j JWTClaimsSet) ToBase64URL() string {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (j JWTClaimsSet) GetClaim(name string) (Claim, error) {
	for _, c := range j.Claims {
		if c.Name == name {
			return c, nil
		}
	}
	return Claim{}, fmt.Errorf("claim %s not found", name)
}

func (j *JWTClaimsSet) AddClaim(c Claim) {
	for i, cl := range j.Claims {
		if cl.Name == c.Name {
			j.Claims[i] = c
			return
		}
	}
	j.Claims = append(j.Claims, c)
}

func (j JWTClaimsSet) GetClaimValue(name string) (interface{}, error) {
	c, err := j.GetClaim(name)
	if err != nil {
		return nil, err
	}
	return c.Value, nil
}

func (j *JWTClaimsSet) SetClaimValue(name string, value interface{}) {
	j.AddClaim(Claim{Name: name, Value: value})
}

func (j *JWTClaimsSet) RemoveClaim(name string) {
	for i, c := range j.Claims {
		if c.Name == name {
			j.Claims = append(j.Claims[:i], j.Claims[i+1:]...)
			return
		}
	}
}

func (j JWTClaimsSet) GetClaimNames() []string {
	names := make([]string, len(j.Claims))
	for i, c := range j.Claims {
		names[i] = c.Name
	}
	return names
}

type Claim struct {
	Name  string
	Value interface{}
}

func (c Claim) String() string {
	out, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func (j JWT) String() string {
	out := j.header.ToBase64URL() + "." +
		j.payload.ToBase64URL()
	if len(j.signature) == 0 {
		return out
	}
	return out + "." +
		base64.URLEncoding.EncodeToString(j.signature)
}

func (j JWT) IsSecured() bool {
	return len(j.signature) > 0
}

type JoseHeader map[string]interface{}

func (j JoseHeader) ToBase64URL() string {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (j JoseHeader) Algorithm() string {
	return j["alg"].(string)
}

func (j JoseHeader) Parameter(key string) interface{} {
	return j[key]
}

func ParseJWT(jwt string) (JWT, error) {
	if jwt == "" {
		return JWT{}, fmt.Errorf("empty JWT")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return JWT{}, fmt.Errorf("invalid JWT")
	}
	header, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWT{}, err
	}
	var h JoseHeader
	if err := json.Unmarshal(header, &h); err != nil {
		return JWT{}, err
	}
	return JWT{
		header:  h,
		payload: JWTClaimsSet{},
		raw:     jwt,
	}, nil
}
