package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func getVerificationKey(authServiceURL string) (ed25519.PublicKey, error) {
	resp, err := http.Get(fmt.Sprintf("%s/auth/verification-key", authServiceURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error calling verification key endpoint: %w\n", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w\n", err)
	}

	decodedKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("error decoding key: %w\n", err)
	}

	if len(decodedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected key length")
	}

	return ed25519.PublicKey(decodedKey), nil
}
