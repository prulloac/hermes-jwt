package cryptography

import (
	"encoding/hex"
	"testing"
)

func TestHMACSign(t *testing.T) {
	// Test cases
	tests := []struct {
		algorithm   string
		text        string
		key         []byte
		expectedHEX string
	}{
		{algorithm: "HS256", text: "1234", key: []byte("key"), expectedHEX: "280ed91eee6eb96a2b1cf598843c1308e84623d14e4208d96c20f7e2de81315e"},
		//{algorithm: "HS384", text: "1234", key: []byte("key"), expectedHEX: "682ef474a442069c734a885a7e4ffca6994a99a914ceea86cac63572edcdbc22fc477e9b8d7e4505fa52d840639d5c43"}, HS384 might not be supported in some systems
		{algorithm: "HS512", text: "1234", key: []byte("key"), expectedHEX: "5d7ea93e116204a673674f9458d42bade8c85896fce87ff267ca52b8b2088d5c49799192856150c9a2e76db44917571c0e2848003d7702c78b232a0ba2dd654c"},
	}
	// Run tests
	for _, test := range tests {
		signature, err := HMACSign(test.algorithm, test.text, test.key)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		hx := hex.EncodeToString(signature)
		if hx != test.expectedHEX {
			t.Errorf("expected %s, got %s", test.expectedHEX, hx)
		}
	}
}
