package notes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024 // 64 MB (OWASP 2024 minimum)
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLen     = 16
	argonKeyLen      = 32 // AES-256
)

type argon2idParams struct {
	Memory      uint32 `json:"m"`
	Iterations  uint32 `json:"t"`
	Parallelism uint8  `json:"p"`
	SaltB64     string `json:"s"`
	HashB64     string `json:"h"`
}

// HashPassword hashes a password using Argon2id and returns a self-describing JSON string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	params := argon2idParams{
		Memory:      argonMemory,
		Iterations:  argonIterations,
		Parallelism: argonParallelism,
		SaltB64:     base64.StdEncoding.EncodeToString(salt),
		HashB64:     base64.StdEncoding.EncodeToString(hash),
	}
	data, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// VerifyPassword checks whether password matches a stored Argon2id hash in constant time.
func VerifyPassword(password, storedHash string) bool {
	var params argon2idParams
	if err := json.Unmarshal([]byte(storedHash), &params); err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(params.SaltB64)
	if err != nil {
		return false
	}
	expectedHash, err := base64.StdEncoding.DecodeString(params.HashB64)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(computed, expectedHash) == 1
}

// DeriveKey derives a 32-byte AES-256 key from password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
}

// Encrypt encrypts plaintext with AES-256-GCM and prefixes it with "enc:".
func Encrypt(password string, plaintext []byte) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := DeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	blob := append(salt, ciphertext...)
	return "enc:" + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt decrypts an "enc:..." string produced by Encrypt.
func Decrypt(password string, encoded string) ([]byte, error) {
	encoded = strings.TrimPrefix(encoded, "enc:")
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(blob) < argonSaltLen+12+16 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	salt := blob[:argonSaltLen]
	rest := blob[argonSaltLen:]
	key := DeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}
	nonce, ciphertext := rest[:nonceSize], rest[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// IsEncrypted reports whether content starts with the "enc:" prefix.
func IsEncrypted(content string) bool {
	return strings.HasPrefix(content, "enc:")
}
