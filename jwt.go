// Reference: https://datatracker.ietf.org/doc/html/rfc7519
package hermes

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const JWT_MEDIA_TYPE = "application/jwt"
const JWT_URN = "urn:ietf:params:oauth:token-type:jwt"

type JWT struct {
	Header    JoseHeader
	Payload   JWTClaimsSet
	Signature []byte
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
	return Claim{}, errors.New(fmt.Sprintf("claim %s not found", name))
}

func (j JWTClaimsSet) AddClaim(c Claim) {
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

func (j JWTClaimsSet) SetClaimValue(name string, value interface{}) {
	j.AddClaim(Claim{Name: name, Value: value})
}

func (j JWTClaimsSet) RemoveClaim(name string) {
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
	return fmt.Sprintf("%s: %v", c.Name, c.Value)
}

func (j JWT) String() string {
	out := j.Header.ToBase64URL() + "." +
		j.Payload.ToBase64URL()
	if len(j.Signature) == 0 {
		return out
	}
	return out + "." +
		base64.URLEncoding.EncodeToString(j.Signature)
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
