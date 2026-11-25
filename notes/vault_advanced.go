package notes

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	RecoveryKeyBytes = 32
	RecoveryNonceLen = 12
	RecoveryPrefix   = "rk:"
	totpDigits       = 6
	totpPeriodSec    = 30
	backupCharset    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// CiphertextMetadata exposes cryptographic envelope telemetry for E2EE Drive and Vault inspection.
type CiphertextMetadata struct {
	Algorithm       string `json:"algorithm"`
	KDF             string `json:"kdf"`
	SaltHex         string `json:"saltHex"`
	NonceHex        string `json:"nonceHex"`
	TagBytes        int    `json:"tagBytes"`
	CiphertextBytes int    `json:"ciphertextBytes"`
	OverheadBytes   int    `json:"overheadBytes"`
	SHA256Hex       string `json:"sha256Hex"`
	Status          string `json:"status"`
}

// InspectCiphertext extracts non-sensitive cryptographic header parameters (salt, nonce, overhead, SHA-256)
// from an "enc:..." blob without requiring the decryption key.
func InspectCiphertext(encoded string, plainBytes []byte) (CiphertextMetadata, error) {
	raw := strings.TrimPrefix(encoded, "enc:")
	blob, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return CiphertextMetadata{}, fmt.Errorf("decoding ciphertext base64: %w", err)
	}
	if len(blob) < argonSaltLen+12+16 {
		return CiphertextMetadata{}, fmt.Errorf("ciphertext blob too short (%d bytes)", len(blob))
	}
	salt := blob[:argonSaltLen]
	nonce := blob[argonSaltLen : argonSaltLen+12]
	digestSource := blob
	if len(plainBytes) > 0 {
		digestSource = plainBytes
	}
	sum := sha256.Sum256(digestSource)
	overhead := argonSaltLen + 12 + 16
	return CiphertextMetadata{
		Algorithm:       "AES-256-GCM",
		KDF:             "Argon2id (m=65536, t=3, p=2)",
		SaltHex:         hex.EncodeToString(salt),
		NonceHex:        hex.EncodeToString(nonce),
		TagBytes:        16,
		CiphertextBytes: len(blob),
		OverheadBytes:   overhead,
		SHA256Hex:       hex.EncodeToString(sum[:]),
		Status:          "E2EE_SEALED",
	}, nil
}

// EncryptBinary encrypts raw binary bytes using a pre-derived 32-byte key and 16-byte salt.
// Binary format: salt(16) | nonce(12) | ciphertext+tag(16).
func EncryptBinary(derivedKey []byte, salt []byte, plaintext []byte) ([]byte, error) {
	if len(derivedKey) != argonKeyLen {
		return nil, fmt.Errorf("invalid derived key length: %d", len(derivedKey))
	}
	if len(salt) != argonSaltLen {
		return nil, fmt.Errorf("invalid salt length: %d", len(salt))
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	out := make([]byte, 0, len(salt)+len(sealed))
	out = append(out, salt...)
	out = append(out, sealed...)
	return out, nil
}

// DecryptBinary decrypts binary data produced by EncryptBinary using a 32-byte derived key.
func DecryptBinary(derivedKey []byte, blob []byte) ([]byte, error) {
	if len(derivedKey) != argonKeyLen {
		return nil, fmt.Errorf("invalid derived key length: %d", len(derivedKey))
	}
	if len(blob) < argonSaltLen+12+16 {
		return nil, fmt.Errorf("encrypted binary too short")
	}
	rest := blob[argonSaltLen:]
	block, err := aes.NewCipher(derivedKey)
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

// ── Recovery Key System (Zero-Knowledge Key Wrapping) ──────────────────────

// GenerateRecoveryKey generates 32 random bytes (256-bit recovery key) and its formatted string.
func GenerateRecoveryKey() ([]byte, string, error) {
	key := make([]byte, RecoveryKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", err
	}
	return key, FormatRecoveryKey(key), nil
}

// FormatRecoveryKey formats a 32-byte key as 8 hyphen-separated uppercase hex groups (XXXX-XXXX-...).
func FormatRecoveryKey(key []byte) string {
	upperHex := strings.ToUpper(hex.EncodeToString(key))
	var groups []string
	for i := 0; i < len(upperHex); i += 8 {
		end := i + 8
		if end > len(upperHex) {
			end = len(upperHex)
		}
		groups = append(groups, upperHex[i:end])
	}
	return strings.Join(groups, "-")
}

// ParseRecoveryKey parses a formatted recovery key string back into 32 bytes.
func ParseRecoveryKey(formatted string) ([]byte, error) {
	var clean strings.Builder
	for _, r := range formatted {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			clean.WriteRune(r)
		}
	}
	hexStr := clean.String()
	if len(hexStr) != RecoveryKeyBytes*2 {
		return nil, fmt.Errorf("invalid recovery key: expected 64 hex chars, got %d", len(hexStr))
	}
	return hex.DecodeString(hexStr)
}

// WrapSecretWithRecoveryKey encrypts a secret (such as master password or derived key) using the 32-byte recovery key.
func WrapSecretWithRecoveryKey(recoveryKey []byte, secret []byte) (string, error) {
	if len(recoveryKey) != RecoveryKeyBytes {
		return "", fmt.Errorf("recovery key must be %d bytes", RecoveryKeyBytes)
	}
	block, err := aes.NewCipher(recoveryKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, RecoveryNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, secret, nil)
	return RecoveryPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// UnwrapSecretWithRecoveryKey decrypts a wrapped secret blob ("rk:...") using the 32-byte recovery key.
func UnwrapSecretWithRecoveryKey(recoveryKey []byte, wrapped string) ([]byte, error) {
	if len(recoveryKey) != RecoveryKeyBytes {
		return nil, fmt.Errorf("recovery key must be %d bytes", RecoveryKeyBytes)
	}
	stripped := strings.TrimPrefix(wrapped, RecoveryPrefix)
	blob, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, err
	}
	if len(blob) < RecoveryNonceLen+16 {
		return nil, fmt.Errorf("invalid recovery blob: too short")
	}
	block, err := aes.NewCipher(recoveryKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := blob[:RecoveryNonceLen], blob[RecoveryNonceLen:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ── RFC 6238 TOTP 2FA & Single-Use Backup Codes ────────────────────────────

// GenerateTOTPSecret generates a 20-byte random secret encoded in Base32 (without padding).
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// BuildTOTPURI constructs an otpauth://totp/ URI suitable for authenticator apps.
func BuildTOTPURI(secretBase32, accountLabel, issuer string) string {
	if issuer == "" {
		issuer = "Writtt Vault"
	}
	if accountLabel == "" {
		accountLabel = "local-vault@writtt"
	}
	v := url.Values{}
	v.Set("secret", strings.ToUpper(strings.TrimSpace(secretBase32)))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s:%s?%s", url.PathEscape(issuer), url.PathEscape(accountLabel), v.Encode())
}

// ComputeTOTPCodeAt computes the 6-digit RFC 6238 TOTP code for a given timestamp.
func ComputeTOTPCodeAt(secretBase32 string, at time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secretBase32), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "="))
	if err != nil {
		return "", fmt.Errorf("invalid base32 TOTP secret: %w", err)
	}
	counter := uint64(at.Unix() / totpPeriodSec)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset]&0x7f) << 24) |
		(int(sum[offset+1]&0xff) << 16) |
		(int(sum[offset+2]&0xff) << 8) |
		int(sum[offset+3]&0xff)
	otp := binCode % 1_000_000
	return fmt.Sprintf("%06d", otp), nil
}

// VerifyTOTPCodeAt verifies a 6-digit TOTP code allowing a +/- 1 time step window (30s tolerance).
// Returns (valid, timeStepBucket) where timeStepBucket can be fed to a ReplayWindow.
func VerifyTOTPCodeAt(secretBase32, code string, at time.Time) (bool, uint64) {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != totpDigits {
		return false, 0
	}
	baseStep := uint64(at.Unix() / totpPeriodSec)
	for delta := int64(-1); delta <= 1; delta++ {
		checkTime := time.Unix((int64(baseStep)+delta)*totpPeriodSec, 0)
		expected, err := ComputeTOTPCodeAt(secretBase32, checkTime)
		if err == nil && expected == trimmed {
			return true, uint64(int64(baseStep) + delta)
		}
	}
	return false, 0
}

// GenerateBackupCodes generates count human-readable backup codes (XXXX-XXXX) and their SHA-256 hashes.
func GenerateBackupCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		count = 8
	}
	plain := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, nil, err
		}
		var b strings.Builder
		for j := 0; j < 8; j++ {
			b.WriteByte(backupCharset[int(raw[j])%len(backupCharset)])
		}
		s := b.String()
		formatted := s[:4] + "-" + s[4:]
		plain = append(plain, formatted)
		hashes = append(hashes, HashBackupCode(formatted))
	}
	return plain, hashes, nil
}

// HashBackupCode computes the normalized SHA-256 hex digest of a backup code.
func HashBackupCode(code string) string {
	norm := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// VerifyBackupCode checks whether code matches any hash in hashes, returning the matched index or -1.
func VerifyBackupCode(code string, hashes []string) int {
	target := HashBackupCode(code)
	for i, h := range hashes {
		if h == target {
			return i
		}
	}
	return -1
}

// ── RSA-2048 OAEP Hybrid Zero-Knowledge Express Envelopes ──────────────────

type RSAKeyPairBundle struct {
	PublicKeyPEM  string `json:"publicKeyPem"`
	PrivateKeyPEM string `json:"privateKeyPem"`
	Fingerprint   string `json:"fingerprint"`
	CreatedAt     string `json:"createdAt"`
}

type ExpressEnvelope struct {
	ID                   string `json:"id"`
	SenderAlias          string `json:"senderAlias"`
	RecipientFingerprint string `json:"recipientFingerprint"`
	Subject              string `json:"subject"`
	WrappedKeyB64        string `json:"wrappedKeyB64"`
	EncryptedPayloadB64  string `json:"encryptedPayloadB64"`
	ContentSHA256        string `json:"contentSha256"`
	CreatedAt            string `json:"createdAt"`
	Read                 bool   `json:"read"`
}

// GenerateRSAKeyPair generates a 2048-bit RSA keypair for Writtt Express zero-knowledge drops.
func GenerateRSAKeyPair() (*RSAKeyPairBundle, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	fp := sha256.Sum256(pubBytes)

	return &RSAKeyPairBundle{
		PublicKeyPEM:  string(pubPEM),
		PrivateKeyPEM: string(privPEM),
		Fingerprint:   hex.EncodeToString(fp[:16]),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// SealExpressEnvelope encrypts plaintext with an ephemeral 256-bit AES-GCM key and wraps that key with RSA-2048 OAEP SHA-256.
func SealExpressEnvelope(recipientPubKeyPEM, senderAlias, subject string, plaintext []byte) (*ExpressEnvelope, error) {
	block, _ := pem.Decode([]byte(recipientPubKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid recipient public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	ephemeralKey := make([]byte, 32)
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, ephemeralKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	cipherPayload, err := EncryptBinary(ephemeralKey, salt, plaintext)
	if err != nil {
		return nil, err
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, ephemeralKey, nil)
	if err != nil {
		return nil, err
	}

	fp := sha256.Sum256(block.Bytes)
	contentSum := sha256.Sum256(plaintext)
	return &ExpressEnvelope{
		ID:                   fmt.Sprintf("exp-%d", time.Now().UnixNano()),
		SenderAlias:          senderAlias,
		RecipientFingerprint: hex.EncodeToString(fp[:16]),
		Subject:              subject,
		WrappedKeyB64:        base64.StdEncoding.EncodeToString(wrappedKey),
		EncryptedPayloadB64:  base64.StdEncoding.EncodeToString(cipherPayload),
		ContentSHA256:        hex.EncodeToString(contentSum[:]),
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// UnsealExpressEnvelope unwraps the ephemeral AES-256 key using the RSA private key and decrypts the payload.
func UnsealExpressEnvelope(recipientPrivKeyPEM string, env ExpressEnvelope) ([]byte, error) {
	block, _ := pem.Decode([]byte(recipientPrivKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid recipient private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(env.WrappedKeyB64)
	if err != nil {
		return nil, err
	}
	ephemeralKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP key unwrap failed: %w", err)
	}
	cipherPayload, err := base64.StdEncoding.DecodeString(env.EncryptedPayloadB64)
	if err != nil {
		return nil, err
	}
	return DecryptBinary(ephemeralKey, cipherPayload)
}

// ── .writttpack Zero-Knowledge Archive & EPUB3 Generator ───────────────────

type PackFileManifest struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"` // "document" | "vault"
	Path     string   `json:"path"`
	Size     int      `json:"size"`
	Tags     []string `json:"tags,omitempty"`
	MimeType string   `json:"mimeType,omitempty"`
}

type PackManifest struct {
	Version   int                `json:"version"`
	PackName  string             `json:"packName"`
	CreatedAt int64              `json:"createdAt"`
	Files     []PackFileManifest `json:"files"`
}

type PackInputItem struct {
	ID        string
	Name      string
	Type      string
	Tags      []string
	MimeType  string
	Plaintext []byte
}

// CreateWritttPack creates an encrypted .writttpack ZIP archive using Argon2id + AES-256-GCM.
func CreateWritttPack(packName, passphrase string, items []PackInputItem) ([]byte, *PackManifest, error) {
	if passphrase == "" {
		return nil, nil, fmt.Errorf("passphrase cannot be empty")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	packKey := DeriveKey(passphrase, salt)

	manifest := &PackManifest{
		Version:   1,
		PackName:  packName,
		CreatedAt: time.Now().UnixMilli(),
		Files:     make([]PackFileManifest, 0, len(items)),
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, item := range items {
		relPath := fmt.Sprintf("files/%s.enc", item.ID)
		encBytes, err := EncryptBinary(packKey, salt, item.Plaintext)
		if err != nil {
			_ = zw.Close()
			return nil, nil, err
		}
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:   relPath,
			Method: zip.Store,
		})
		if err != nil {
			_ = zw.Close()
			return nil, nil, err
		}
		if _, err := w.Write(encBytes); err != nil {
			_ = zw.Close()
			return nil, nil, err
		}
		manifest.Files = append(manifest.Files, PackFileManifest{
			ID:       item.ID,
			Name:     item.Name,
			Type:     item.Type,
			Path:     relPath,
			Size:     len(item.Plaintext),
			Tags:     item.Tags,
			MimeType: item.MimeType,
		})
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		_ = zw.Close()
		return nil, nil, err
	}
	encManifest, err := EncryptBinary(packKey, salt, manifestJSON)
	if err != nil {
		_ = zw.Close()
		return nil, nil, err
	}
	mw, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "manifest.json.enc",
		Method: zip.Store,
	})
	if err != nil {
		_ = zw.Close()
		return nil, nil, err
	}
	if _, err := mw.Write(encManifest); err != nil {
		_ = zw.Close()
		return nil, nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), manifest, nil
}

// ParseWritttPack decrypts and extracts a .writttpack archive using passphrase.
func ParseWritttPack(packBytes []byte, passphrase string) (*PackManifest, map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(packBytes), int64(len(packBytes)))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid .writttpack zip: %w", err)
	}
	filesMap := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		filesMap[f.Name] = f
	}
	mf, ok := filesMap["manifest.json.enc"]
	if !ok {
		return nil, nil, fmt.Errorf("manifest.json.enc missing in pack")
	}
	rc, err := mf.Open()
	if err != nil {
		return nil, nil, err
	}
	encManifest, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, nil, err
	}
	if len(encManifest) < argonSaltLen+12+16 {
		return nil, nil, fmt.Errorf("corrupted manifest size")
	}
	salt := encManifest[:argonSaltLen]
	packKey := DeriveKey(passphrase, salt)
	plainManifest, err := DecryptBinary(packKey, encManifest)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid pack passphrase: %w", err)
	}
	var manifest PackManifest
	if err := json.Unmarshal(plainManifest, &manifest); err != nil {
		return nil, nil, err
	}

	extracted := make(map[string][]byte, len(manifest.Files))
	for _, entry := range manifest.Files {
		zf, exists := filesMap[entry.Path]
		if !exists {
			continue
		}
		frc, err := zf.Open()
		if err != nil {
			continue
		}
		cipherData, err := io.ReadAll(frc)
		_ = frc.Close()
		if err != nil {
			continue
		}
		plain, err := DecryptBinary(packKey, cipherData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed decrypting pack file %s: %w", entry.ID, err)
		}
		extracted[entry.ID] = plain
	}
	return &manifest, extracted, nil
}

// GenerateEPUB3 builds a valid EPUB 3.0 archive from title, language, and XHTML-safe body content.
func GenerateEPUB3(title, author, lang, htmlBody string) ([]byte, error) {
	if title == "" {
		title = "Untitled Document"
	}
	if author == "" {
		author = "Writtt Studio"
	}
	if lang == "" {
		lang = "pt-BR"
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// 1. mimetype must be first and uncompressed
	mimeWriter, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "mimetype",
		Method: zip.Store,
	})
	if err != nil {
		return nil, err
	}
	if _, err := mimeWriter.Write([]byte("application/epub+zip")); err != nil {
		return nil, err
	}

	writeTextFile := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}

	containerXML := `<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>`
	if err := writeTextFile("META-INF/container.xml", containerXML); err != nil {
		return nil, err
	}

	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	uid := fmt.Sprintf("urn:uuid:writtt-%d", time.Now().UnixNano())
	contentOPF := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="BookId">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>%s</dc:title>
    <dc:creator>%s</dc:creator>
    <dc:language>%s</dc:language>
    <dc:identifier id="BookId">%s</dc:identifier>
    <meta property="dcterms:modified">%s</meta>
  </metadata>
  <manifest>
    <item id="content" href="content.xhtml" media-type="application/xhtml+xml"/>
    <item id="toc" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
  </manifest>
  <spine toc="toc">
    <itemref idref="content"/>
  </spine>
</package>`, xmlEscape(title), xmlEscape(author), xmlEscape(lang), uid, nowISO)
	if err := writeTextFile("OEBPS/content.opf", contentOPF); err != nil {
		return nil, err
	}

	tocNCX := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head>
    <meta name="dtb:uid" content="%s"/>
    <meta name="dtb:depth" content="1"/>
  </head>
  <docTitle><text>%s</text></docTitle>
  <navMap>
    <navPoint id="navPoint-1" playOrder="1">
      <navLabel><text>%s</text></navLabel>
      <content src="content.xhtml"/>
    </navPoint>
  </navMap>
</ncx>`, uid, xmlEscape(title), xmlEscape(title))
	if err := writeTextFile("OEBPS/toc.ncx", tocNCX); err != nil {
		return nil, err
	}

	contentXHTML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="%s">
<head>
  <meta charset="utf-8" />
  <title>%s</title>
  <style type="text/css">
    body { font-family: Georgia, serif; line-height: 1.65; margin: 2em; color: #18181b; }
    h1, h2, h3 { font-family: sans-serif; color: #09090b; }
    pre, code { font-family: monospace; background: #f4f4f5; padding: 2px 4px; }
    blockquote { border-left: 3px solid #6366f1; padding-left: 1em; color: #52525b; }
  </style>
</head>
<body>
  <h1>%s</h1>
  %s
</body>
</html>`, xmlEscape(lang), xmlEscape(title), xmlEscape(title), htmlBody)
	if err := writeTextFile("OEBPS/content.xhtml", contentXHTML); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
