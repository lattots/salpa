package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lattots/salpa/public/client"
)

func TestGetVerificationKey(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %s", err)
	}

	// This is mocks the actual handler.TestGetVerificationKey function
	mockHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			http.Error(w, "failed to marshal key", http.StatusInternalServerError)
			return
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		}
		if err := pem.Encode(w, pemBlock); err != nil {
			http.Error(w, "failed to encode pem", http.StatusInternalServerError)
			return
		}
	}

	router := http.NewServeMux()
	router.HandleFunc("GET /auth/verification-key", mockHandler)

	server := httptest.NewServer(router)
	defer server.Close()

	fetchedKey, err := client.GetVerificationKey(server.URL)
	if err != nil {
		t.Fatalf("getVerificationKey returned unexpected error: %s", err)
	}

	if !bytes.Equal(fetchedKey, pubKey) {
		t.Errorf("Keys do not match.\nExpected: %x\nGot:      %x", pubKey, fetchedKey)
	}
}
