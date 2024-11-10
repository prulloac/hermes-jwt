package cryptography

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

const RSA_PRIVATE_KEY = `
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDAiT2frVV4IyQJkEARAN2C0zbK8v/hiNZUvGWNZfLEtdRGVluG
28AJa9MUTh3Sl37SnjRR+Zs1pihHY9LhtODPS156/QeTlSCfsyJGqbduSWo0ZAlg
tgo3ZWazsjcd7E+5Fz+8uz0fXW/RQz4ttKxTMdz8b+DTJ/h1i6iAGh6yMwIDAQAB
AoGACBW7QLlGnYTcPoqQJiajJps38c3CcPYOCgDfQtDFIP2BrHJz5XXU2pBsjK27
EtzJto5uJAMXQWl4x4aplFDEH92kAcz1jFr54+Ui3/i5Yc1q312Cid0NIkiW6Wff
FqvLSn/eqBUN/XjtKE8YsPolWQBqhrC5TZRwpvqNuslYqgECQQDizyqx4XY9y6hW
DFt+qEziwyIAWaPqg69cfoiZvVhEpJMSP19MKBZAQ6kavvjpZwksv425fEotbZvF
eNHCsZenAkEA2VDan01vJx99aFzipblQZXk7SLf7WEUa2el4mqmJG5Q8y5dwcAFz
oiMcmYUnIn8K+OE8jLgKrU+98Ok7FCDilQJBALJK5Gccs1R0ignKgQoZxwbjGhFo
ZgBuMCXnmf4w5/hd3vcTNhip0oQGLCLISOdBhebVVdWfrLf1V+Rty4bfEDUCQQCs
OPmpuhJW7QvUA5jTQbPHV3Z2QOh+ofWPsQmVeLpiEu7DYncHLP9ZBX6K5A2JtykY
6Fe2JbzAcSvUmuHpJ86pAkAXTotXFB47II+Oz+9SvZ0y09jWMiqgMt5w5zG5Drba
epXGI6SxF6fj4gHwViXv8uEuLolONDoV/tAzNbt4BRG8
-----END RSA PRIVATE KEY-----
`

const RSA_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIGJAoGBAMCJPZ+tVXgjJAmQQBEA3YLTNsry/+GI1lS8ZY1l8sS11EZWW4bbwAlr
0xROHdKXftKeNFH5mzWmKEdj0uG04M9LXnr9B5OVIJ+zIkapt25JajRkCWC2Cjdl
ZrOyNx3sT7kXP7y7PR9db9FDPi20rFMx3Pxv4NMn+HWLqIAaHrIzAgMBAAE=
-----END PUBLIC KEY-----
`

func TestHMAC(t *testing.T) {
	// Test cases
	tests := []struct {
		algorithm   string
		expectedHEX string
	}{
		{algorithm: "HS256", expectedHEX: "280ed91eee6eb96a2b1cf598843c1308e84623d14e4208d96c20f7e2de81315e"},
		{algorithm: "HS384", expectedHEX: "682ef474a442069c734a885a7e4ffca6994a99a914ceea86cac63572edcdbc22fc477e9b8d7e4505fa52d840639d5c43"},
		{algorithm: "HS512", expectedHEX: "5d7ea93e116204a673674f9458d42bade8c85896fce87ff267ca52b8b2088d5c49799192856150c9a2e76db44917571c0e2848003d7702c78b232a0ba2dd654c"},
	}
	// Run tests
	for _, test := range tests {
		signature, err := HMACSign(test.algorithm, []byte("key"), "1234")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		hx := hex.EncodeToString(signature)
		if hx != test.expectedHEX {
			t.Errorf("expected %s, got %s", test.expectedHEX, hx)
		}
		verify, err := HMACVerify(test.algorithm, []byte("key"), "1234", signature)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !verify {
			t.Errorf("expected true, got false")
		}
	}
}

func TestRSA(t *testing.T) {
	// Test cases
	block, _ := pem.Decode([]byte(RSA_PRIVATE_KEY))
	private, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(RSA_PUBLIC_KEY))
	public, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	b64Encoder := base64.StdEncoding
	tests := []struct {
		algorithm      string
		text           string
		expectedBase64 string
	}{
		{algorithm: "RS256", expectedBase64: "g3eHfgTLvZ/T6yXTM9fYZ5eq/7DGE0/53WOEbYBL0Lb3vk9hjWlHnDgxdr2UHYEATiFA1BVCcDNgJyDk/lzM2fdzw+Mxi+3bOYIpwnMKjO0SGUEcycyGBGwzgew/FLmPNV9Ps2zcVSXOHwttSZOKGhWwu3ZJBuS2xRftnGGTNBE="},
		{algorithm: "RS384", expectedBase64: "CJKe0nAR2HglvFbQi2GNgIIbQZIWFcfqUgUY5Rl+c20zaXDaTncySZIFps011i8G0++OmNDA4TAdpwqH8OVJ5gm10ifSjK5STulWy3rdipy9slIYRm3CsK66H67eWrAoclKlM59s7rC/ac6cYsN8EZOnjrroggGqdOSETV93aEY="},
		{algorithm: "RS512", expectedBase64: "BPpxMurZf3liU3X2qfm1nwuG2tF46TRaXahWtvDKMqrXx8b4PoXODZlcqCyf9qNq5BlL/krGnyeQWvCeY7jfwoveaGHfLoNEGAqsYQ71Zr8jrcpoPyx6E1B1S9UQYMeefKmfkVt1w0F3LPNWMCxRfnH7jISrFDYwvIjhSbtpiE8="},
	}

	// Run tests
	for _, test := range tests {
		signature, err := RSASign(test.algorithm, private, "1234")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		b64 := b64Encoder.EncodeToString(signature)
		if b64 != test.expectedBase64 {
			t.Errorf("expected %s, got %s", test.expectedBase64, b64)
		}
		verify, err := RSAVerify(test.algorithm, public, "1234", signature)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !verify {
			t.Errorf("expected true, got false")
		}
	}
}
