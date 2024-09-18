package hermes

type JWT interface {
	Header() Header
	Payload() (Payload, error)
	Signature() []byte
	Verify() bool
}

type Header interface {
	Algorithm() string
	Parameter(string) interface{}
	toMap() map[string]interface{}
}

type JoseHeader map[string]interface{}

type Payload interface {
	JWTID() string
	Subject() string
	Claims() map[string]interface{}
	Raw() []byte
}

type HeaderParameter string

func (j JoseHeader) Algorithm() string {
	return j["alg"].(string)
}

func (j JoseHeader) Parameter(key string) interface{} {
	return j[key]
}

func (j JoseHeader) toMap() map[string]interface{} {
	return j
}
