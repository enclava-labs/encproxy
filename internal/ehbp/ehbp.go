package ehbp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// Constants for EHBP protocol.
const (
	AES256KeyLength         = 32
	AESGCMNonceLength       = 12
	X25519KeyLength         = 32
	HashLength              = 32
	HPKEExportLength        = 32
	EHBPResponseNonceLength = 32
)

var (
	HPKEKEM  = hpke.KEM_X25519_HKDF_SHA256
	HPKEKDF  = hpke.KDF_HKDF_SHA256
	HPKEAEAD = hpke.AEAD_AES256GCM
)

// KeyConfig represents parsed EHBP key configuration.
type KeyConfig struct {
	KeyID        uint8
	KEMID        uint16
	PublicKey    []byte
	CipherSuites [][2]uint16 // [KDF, AEAD] pairs
}

// EncryptedRequest represents an EHBP encrypted request.
type EncryptedRequest struct {
	EncapsulatedKey []byte
	Body            []byte
	ExportedSecret  []byte
}

// ResponseKeys holds derived keys for response decryption.
type ResponseKeys struct {
	Key       []byte
	NonceBase []byte
}

// PublicKeyDigest returns the SHA-256 digest of a public key.
func PublicKeyDigest(key []byte) string {
	h := sha256.Sum256(key)
	return fmt.Sprintf("sha256:%x", h)
}

// ParseKeyConfig parses an EHBP key configuration.
func ParseKeyConfig(data []byte) (*KeyConfig, error) {
	if len(data) < 1+2+2 {
		return nil, fmt.Errorf("invalid EHBP key config: too short (%d bytes)", len(data))
	}

	offset := 0
	keyID := data[offset]
	offset++

	kemID := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	publicKeySize := 32 // X25519
	if kemID != 0x0020 {
		return nil, fmt.Errorf("unsupported KEM: 0x%04x", kemID)
	}

	if offset+publicKeySize > len(data) {
		return nil, fmt.Errorf("truncated public key")
	}
	publicKey := data[offset : offset+publicKeySize]
	offset += publicKeySize

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated cipher suite length")
	}
	suitesLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if suitesLen == 0 {
		return nil, fmt.Errorf("no cipher suites")
	}
	if suitesLen%4 != 0 {
		return nil, fmt.Errorf("malformed cipher suite list")
	}
	if offset+int(suitesLen) > len(data) {
		return nil, fmt.Errorf("truncated cipher suite list")
	}

	suitesEnd := offset + int(suitesLen)
	var cipherSuites [][2]uint16
	for offset < suitesEnd {
		kdfID := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		aeadID := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		cipherSuites = append(cipherSuites, [2]uint16{kdfID, aeadID})
	}

	if offset != len(data) {
		return nil, fmt.Errorf("trailing bytes in key config")
	}

	// Validate supported configuration
	if keyID != 0 {
		return nil, fmt.Errorf("unsupported key ID: %d", keyID)
	}
	if kemID != 0x0020 { // X25519
		return nil, fmt.Errorf("unsupported KEM: 0x%04x", kemID)
	}
	if len(cipherSuites) == 0 {
		return nil, fmt.Errorf("no cipher suites")
	}
	if cipherSuites[0] != [2]uint16{0x0001, 0x0002} { // HKDF-SHA256, AES-256-GCM
		return nil, fmt.Errorf("unsupported cipher suite")
	}

	return &KeyConfig{
		KeyID:        keyID,
		KEMID:        kemID,
		PublicKey:    publicKey,
		CipherSuites: cipherSuites,
	}, nil
}

// EncryptRequest encrypts a request body using EHBP.
func EncryptRequest(keyConfig []byte, plaintext []byte) (*EncryptedRequest, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("EHBP requires non-empty body")
	}

	kc, err := ParseKeyConfig(keyConfig)
	if err != nil {
		return nil, fmt.Errorf("parse key config: %w", err)
	}

	// Create HPKE suite
	suite := hpke.NewSuite(HPKEKEM, HPKEKDF, HPKEAEAD)

	// Import the recipient's public key
	kemScheme := HPKEKEM.Scheme()
	pubKey, err := kemScheme.UnmarshalBinaryPublicKey(kc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	// Setup sender context
	info := []byte("ehbp request")
	sender, err := suite.NewSender(pubKey, info)
	if err != nil {
		return nil, fmt.Errorf("create sender: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("setup sender: %w", err)
	}

	// Encrypt the plaintext
	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	// Export secret for response decryption using the EHBP/OHTTP exporter label.
	exportedSecret := sealer.Export([]byte("ehbp response"), HPKEExportLength)

	// Frame the ciphertext (length-prefixed)
	framed := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(framed, uint32(len(ciphertext)))
	copy(framed[4:], ciphertext)

	return &EncryptedRequest{
		EncapsulatedKey: enc,
		Body:            framed,
		ExportedSecret:  exportedSecret,
	}, nil
}

// DecryptResponse decrypts an EHBP response body.
func DecryptResponse(exportedSecret, requestEnc, responseNonce, body []byte) ([]byte, error) {
	if len(exportedSecret) != HPKEExportLength {
		return nil, fmt.Errorf("exported secret must be %d bytes, got %d", HPKEExportLength, len(exportedSecret))
	}
	if len(requestEnc) != X25519KeyLength {
		return nil, fmt.Errorf("request enc must be %d bytes, got %d", X25519KeyLength, len(requestEnc))
	}
	if len(responseNonce) != EHBPResponseNonceLength {
		return nil, fmt.Errorf("response nonce must be %d bytes, got %d", EHBPResponseNonceLength, len(responseNonce))
	}

	// Derive response keys using HKDF-like construction
	keys := deriveResponseKeys(exportedSecret, requestEnc, responseNonce)

	// Decrypt framed body
	return openFramedBody(keys.Key, keys.NonceBase, body)
}

// deriveResponseKeys derives the response encryption keys.
func deriveResponseKeys(exportedSecret, requestEnc, responseNonce []byte) *ResponseKeys {
	// salt = request_enc || response_nonce
	salt := append(requestEnc, responseNonce...)

	// PRK = HKDF-Extract(salt, exported_secret)
	prk := hkdfExtract(salt, exportedSecret)

	// Derive key and nonce
	key := hkdfExpand(prk, []byte("key"), AES256KeyLength)
	nonceBase := hkdfExpand(prk, []byte("nonce"), AESGCMNonceLength)

	return &ResponseKeys{
		Key:       key,
		NonceBase: nonceBase,
	}
}

// hkdfExtract performs HKDF extract.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmacSHA256(salt, ikm)
	return mac
}

// hkdfExpand performs HKDF expand.
func hkdfExpand(prk, info []byte, length int) []byte {
	var okm []byte
	var counter byte = 1
	var prev []byte

	for len(okm) < length {
		data := append(prev, info...)
		data = append(data, counter)
		t := hmacSHA256(prk, data)
		okm = append(okm, t...)
		prev = t
		counter++
	}

	return okm[:length]
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// openFramedBody decrypts length-prefixed ciphertext chunks.
func openFramedBody(key, nonceBase, body []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	var plaintext []byte
	offset := 0
	seq := uint64(0)

	for offset < len(body) {
		if offset+4 > len(body) {
			return nil, fmt.Errorf("truncated chunk length at offset %d", offset)
		}
		chunkLen := binary.BigEndian.Uint32(body[offset:])
		offset += 4

		if chunkLen == 0 {
			continue
		}

		if offset+int(chunkLen) > len(body) {
			return nil, fmt.Errorf("truncated ciphertext chunk at offset %d", offset)
		}
		ciphertext := body[offset : offset+int(chunkLen)]
		offset += int(chunkLen)

		nonce := xorNonce(nonceBase, seq)
		chunk, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", seq, err)
		}

		plaintext = append(plaintext, chunk...)
		seq++
	}

	return plaintext, nil
}

// xorNonce XORs the sequence number into the nonce.
func xorNonce(base []byte, seq uint64) []byte {
	if len(base) != AESGCMNonceLength {
		panic("nonce base must be 12 bytes")
	}

	nonce := make([]byte, AESGCMNonceLength)
	copy(nonce, base)

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)

	// XOR the last 8 bytes
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}

	return nonce
}

// EncryptResponseForTest encrypts a response for testing (server-side).
func EncryptResponseForTest(exportedSecret, requestEnc, responseNonce, plaintext []byte) ([]byte, error) {
	if len(exportedSecret) != HPKEExportLength {
		return nil, fmt.Errorf("exported secret must be %d bytes", HPKEExportLength)
	}
	if len(requestEnc) != X25519KeyLength {
		return nil, fmt.Errorf("request enc must be %d bytes", X25519KeyLength)
	}
	if len(responseNonce) != EHBPResponseNonceLength {
		return nil, fmt.Errorf("response nonce must be %d bytes", EHBPResponseNonceLength)
	}

	// Derive response keys
	keys := deriveResponseKeys(exportedSecret, requestEnc, responseNonce)

	// Encrypt and frame
	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := xorNonce(keys.NonceBase, 0)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	framed := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(framed, uint32(len(ciphertext)))
	copy(framed[4:], ciphertext)

	return framed, nil
}

// BuildKeyConfig builds an EHBP key configuration from a public key.
func BuildKeyConfig(publicKey []byte) []byte {
	// Format: key_id(1) || kem_id(2) || public_key(32) || cipher_suites_len(2) || cipher_suites(4)
	config := make([]byte, 0, 1+2+32+2+4)

	// Key ID: 0
	config = append(config, 0)

	// KEM ID: X25519 (big-endian)
	config = append(config, 0x00, 0x20)

	// Public key (32 bytes)
	config = append(config, publicKey...)

	// Cipher suites length: 4 (1 suite)
	config = append(config, 0x00, 0x04)

	// Cipher suite: HKDF-SHA256 || AES-256-GCM
	config = append(config, 0x00, 0x01) // KDF
	config = append(config, 0x00, 0x02) // AEAD

	return config
}

// DecodeHex decodes a hex string (with optional prefix).
func DecodeHex(s string) ([]byte, error) {
	s = hexString(s)
	return hex.DecodeString(s)
}

// hexString removes sha256: prefix from hex strings.
func hexString(s string) string {
	if len(s) > 7 && s[:7] == "sha256:" {
		return s[7:]
	}
	return s
}
