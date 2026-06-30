package ehbp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestBuildKeyConfig(t *testing.T) {
	// Generate a random public key for testing
	pubKey := make([]byte, X25519KeyLength)
	if _, err := rand.Read(pubKey); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	config := BuildKeyConfig(pubKey)

	// Should be 1 (key_id) + 2 (kem_id) + 32 (public_key) + 2 (suites_len) + 4 (suites) = 41 bytes
	if len(config) != 41 {
		t.Errorf("Expected config length 41, got %d", len(config))
	}

	// Parse the config
	kc, err := ParseKeyConfig(config)
	if err != nil {
		t.Fatalf("Failed to parse key config: %v", err)
	}

	if kc.KeyID != 0 {
		t.Errorf("Expected key ID 0, got %d", kc.KeyID)
	}

	if kc.KEMID != 0x0020 {
		t.Errorf("Expected KEM ID 0x0020, got 0x%04x", kc.KEMID)
	}

	if !bytes.Equal(kc.PublicKey, pubKey) {
		t.Errorf("Public key mismatch")
	}
}

func TestRoundTrip(t *testing.T) {
	// Generate a keypair for the recipient
	recipientPubKey := make([]byte, X25519KeyLength)
	if _, err := rand.Read(recipientPubKey); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Build key config
	keyConfig := BuildKeyConfig(recipientPubKey)

	// Plaintext to encrypt
	plaintext := []byte(`{"messages": [{"role": "user", "content": "Hello, world!"}]}`)

	// Encrypt request
	encReq, err := EncryptRequest(keyConfig, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(encReq.EncapsulatedKey) == 0 {
		t.Error("Expected non-empty encapsulated key")
	}

	if len(encReq.Body) == 0 {
		t.Error("Expected non-empty body")
	}

	if len(encReq.ExportedSecret) == 0 {
		t.Error("Expected non-empty exported secret")
	}

	// Generate response nonce
	responseNonce := make([]byte, EHBPResponseNonceLength)
	if _, err := rand.Read(responseNonce); err != nil {
		t.Fatalf("Failed to generate response nonce: %v", err)
	}

	// Encrypt response (simulating server-side)
	responsePlaintext := []byte(`{"choices": [{"message": {"role": "assistant", "content": "Hello!"}}]}`)
	encryptedResponse, err := EncryptResponseForTest(encReq.ExportedSecret, encReq.EncapsulatedKey, responseNonce, responsePlaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt response: %v", err)
	}

	// Decrypt response
	decrypted, err := DecryptResponse(encReq.ExportedSecret, encReq.EncapsulatedKey, responseNonce, encryptedResponse)
	if err != nil {
		t.Fatalf("Failed to decrypt response: %v", err)
	}

	if !bytes.Equal(decrypted, responsePlaintext) {
		t.Errorf("Decrypted mismatch: got %s, want %s", decrypted, responsePlaintext)
	}
}

func TestPublicKeyDigest(t *testing.T) {
	key := []byte("test public key")
	digest := PublicKeyDigest(key)

	if digest[:7] != "sha256:" {
		t.Errorf("Expected sha256: prefix, got %s", digest)
	}

	// Decode the hex part
	hexPart := digest[7:]
	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Errorf("Failed to decode hex: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(decoded))
	}
}

func TestEmptyPlaintextError(t *testing.T) {
	key := make([]byte, X25519KeyLength)
	config := BuildKeyConfig(key)

	_, err := EncryptRequest(config, []byte{})
	if err == nil {
		t.Error("Expected error for empty plaintext")
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	recipientPubKey := make([]byte, X25519KeyLength)
	rand.Read(recipientPubKey)
	keyConfig := BuildKeyConfig(recipientPubKey)
	plaintext := []byte(`{"messages": [{"role": "user", "content": "Hello, world!"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encReq, err := EncryptRequest(keyConfig, plaintext)
		if err != nil {
			b.Fatal(err)
		}

		responseNonce := make([]byte, EHBPResponseNonceLength)
		rand.Read(responseNonce)

		responsePlaintext := []byte(`{"choices": [{"message": {"role": "assistant", "content": "Hello!"}}]}`)
		encryptedResponse, _ := EncryptResponseForTest(encReq.ExportedSecret, encReq.EncapsulatedKey, responseNonce, responsePlaintext)
		DecryptResponse(encReq.ExportedSecret, encReq.EncapsulatedKey, responseNonce, encryptedResponse)
	}
}
