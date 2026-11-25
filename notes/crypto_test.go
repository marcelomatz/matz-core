package notes_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/marcelomatz/matz-core/notes"
)

func TestArgon2idAndAESGCM(t *testing.T) {
	hash, err := notes.HashPassword("master-secret-2026")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !notes.VerifyPassword("master-secret-2026", hash) {
		t.Fatalf("expected VerifyPassword to succeed")
	}
	if notes.VerifyPassword("wrong-password", hash) {
		t.Fatalf("expected VerifyPassword to reject wrong password")
	}

	plain := []byte("# Confidential Architecture\nZero-Knowledge Content.")
	enc, err := notes.Encrypt("master-secret-2026", plain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !notes.IsEncrypted(enc) {
		t.Fatalf("expected enc: prefix")
	}

	meta, err := notes.InspectCiphertext(enc, plain)
	if err != nil {
		t.Fatalf("InspectCiphertext failed: %v", err)
	}
	if meta.Algorithm != "AES-256-GCM" || len(meta.SaltHex) != 32 || len(meta.NonceHex) != 24 {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	dec, err := notes.Decrypt("master-secret-2026", enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("decrypted mismatch: %s", string(dec))
	}
	if _, err := notes.Decrypt("wrong-pass", enc); err == nil {
		t.Fatalf("expected error on wrong password")
	}
}

func TestRecoveryKeyWrapAndUnwrap(t *testing.T) {
	rk, formatted, err := notes.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}
	if len(rk) != 32 || strings.Count(formatted, "-") != 7 {
		t.Fatalf("unexpected recovery key format: %s", formatted)
	}

	parsed, err := notes.ParseRecoveryKey(strings.ToLower(formatted))
	if err != nil || !bytes.Equal(parsed, rk) {
		t.Fatalf("ParseRecoveryKey mismatch: %v", err)
	}

	secret := []byte("vault-master-password-bytes")
	wrapped, err := notes.WrapSecretWithRecoveryKey(rk, secret)
	if err != nil || !strings.HasPrefix(wrapped, "rk:") {
		t.Fatalf("WrapSecretWithRecoveryKey failed: %v", err)
	}

	unwrapped, err := notes.UnwrapSecretWithRecoveryKey(parsed, wrapped)
	if err != nil || !bytes.Equal(unwrapped, secret) {
		t.Fatalf("UnwrapSecretWithRecoveryKey failed: %v", err)
	}
}

func TestTOTPAndBackupCodes(t *testing.T) {
	secret, err := notes.GenerateTOTPSecret()
	if err != nil || secret == "" {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}
	uri := notes.BuildTOTPURI(secret, "user@writtt.local", "Writtt")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("invalid TOTP URI: %s", uri)
	}

	now := time.Unix(1700000000, 0)
	code, err := notes.ComputeTOTPCodeAt(secret, now)
	if err != nil || len(code) != 6 {
		t.Fatalf("ComputeTOTPCodeAt failed: %v (%s)", err, code)
	}

	ok, step := notes.VerifyTOTPCodeAt(secret, code, now.Add(15*time.Second))
	if !ok || step == 0 {
		t.Fatalf("expected TOTP code to verify within window")
	}
	if valid, _ := notes.VerifyTOTPCodeAt(secret, "000000", now); valid && code != "000000" {
		t.Fatalf("expected invalid TOTP code to fail")
	}

	plainCodes, hashes, err := notes.GenerateBackupCodes(8)
	if err != nil || len(plainCodes) != 8 || len(hashes) != 8 {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	idx := notes.VerifyBackupCode(plainCodes[3], hashes)
	if idx != 3 {
		t.Fatalf("expected backup code index 3, got %d", idx)
	}
	if notes.VerifyBackupCode("INVALID-CODE", hashes) != -1 {
		t.Fatalf("expected -1 for invalid backup code")
	}
}

func TestRSAExpressHybridEnvelope(t *testing.T) {
	kp, err := notes.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}
	msg := []byte("Zero-Knowledge Express Drop Payload")
	env, err := notes.SealExpressEnvelope(kp.PublicKeyPEM, "@alice", "Classified Spec", msg)
	if err != nil {
		t.Fatalf("SealExpressEnvelope failed: %v", err)
	}
	opened, err := notes.UnsealExpressEnvelope(kp.PrivateKeyPEM, *env)
	if err != nil {
		t.Fatalf("UnsealExpressEnvelope failed: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("unsealed payload mismatch: %s", string(opened))
	}
}

func TestWritttPackAndEPUB3(t *testing.T) {
	items := []notes.PackInputItem{
		{
			ID:        "01HTESTDOC0000000000000001",
			Name:      "Chapter 1",
			Type:      "vault",
			Tags:      []string{"crypto", "spec"},
			MimeType:  "text/markdown",
			Plaintext: []byte("# Chapter 1\nEncrypted pack content."),
		},
	}
	packBytes, manifest, err := notes.CreateWritttPack("Architecture Backup", "pack-pass-2026", items)
	if err != nil || len(packBytes) == 0 || len(manifest.Files) != 1 {
		t.Fatalf("CreateWritttPack failed: %v", err)
	}

	parsedManifest, extracted, err := notes.ParseWritttPack(packBytes, "pack-pass-2026")
	if err != nil {
		t.Fatalf("ParseWritttPack failed: %v", err)
	}
	if parsedManifest.PackName != "Architecture Backup" {
		t.Fatalf("unexpected pack name: %s", parsedManifest.PackName)
	}
	if string(extracted["01HTESTDOC0000000000000001"]) != "# Chapter 1\nEncrypted pack content." {
		t.Fatalf("unexpected extracted content")
	}
	if _, _, err := notes.ParseWritttPack(packBytes, "wrong-pass"); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}

	epubBytes, err := notes.GenerateEPUB3("The Zero-Knowledge Book", "Marcelo Matz", "pt-BR", "<p>Hello EPUB3</p>")
	if err != nil || len(epubBytes) < 100 {
		t.Fatalf("GenerateEPUB3 failed: %v", err)
	}
	epubDefault, err := notes.GenerateEPUB3("", "", "", "<p>Defaults &amp; Quotes ' \" &lt; &gt;</p>")
	if err != nil || len(epubDefault) < 100 {
		t.Fatalf("GenerateEPUB3 defaults failed: %v", err)
	}
}

func TestNotesErrorPathsAndEdgeCases(t *testing.T) {
	if notes.VerifyPassword("pw", "not-json") {
		t.Fatalf("expected invalid json hash to fail")
	}
	if notes.VerifyPassword("pw", `{"s":"!!!","h":"YWJj"}`) {
		t.Fatalf("expected invalid salt base64 to fail")
	}
	if notes.VerifyPassword("pw", `{"s":"YWJj","h":"!!!"}`) {
		t.Fatalf("expected invalid hash base64 to fail")
	}
	if _, err := notes.Decrypt("pw", "enc:!!!"); err == nil {
		t.Fatalf("expected invalid base64 to fail")
	}
	if _, err := notes.Decrypt("pw", "enc:YWJj"); err == nil {
		t.Fatalf("expected short blob to fail")
	}
	if _, err := notes.InspectCiphertext("enc:!!!", nil); err == nil {
		t.Fatalf("expected invalid base64 to fail InspectCiphertext")
	}
	if _, err := notes.InspectCiphertext("enc:YWJj", nil); err == nil {
		t.Fatalf("expected short blob to fail InspectCiphertext")
	}
	if _, err := notes.EncryptBinary([]byte("short"), make([]byte, 16), []byte("x")); err == nil {
		t.Fatalf("expected invalid key length to fail")
	}
	if _, err := notes.EncryptBinary(make([]byte, 32), []byte("short"), []byte("x")); err == nil {
		t.Fatalf("expected invalid salt length to fail")
	}
	if _, err := notes.DecryptBinary([]byte("short"), make([]byte, 64)); err == nil {
		t.Fatalf("expected invalid key length to fail")
	}
	if _, err := notes.DecryptBinary(make([]byte, 32), []byte("short")); err == nil {
		t.Fatalf("expected short binary to fail")
	}
	if _, err := notes.ParseRecoveryKey("too-short"); err == nil {
		t.Fatalf("expected short recovery key to fail")
	}
	if _, err := notes.WrapSecretWithRecoveryKey([]byte("short"), []byte("s")); err == nil {
		t.Fatalf("expected short recovery key to fail wrap")
	}
	if _, err := notes.UnwrapSecretWithRecoveryKey([]byte("short"), "rk:YWJj"); err == nil {
		t.Fatalf("expected short recovery key to fail unwrap")
	}
	if _, err := notes.UnwrapSecretWithRecoveryKey(make([]byte, 32), "rk:!!!"); err == nil {
		t.Fatalf("expected invalid base64 to fail unwrap")
	}
	if _, err := notes.UnwrapSecretWithRecoveryKey(make([]byte, 32), "rk:YWJj"); err == nil {
		t.Fatalf("expected short blob to fail unwrap")
	}
	if uri := notes.BuildTOTPURI("JBSWY3DPEHPK3PXP", "", ""); !strings.Contains(uri, "Writtt") {
		t.Fatalf("expected default issuer in URI: %s", uri)
	}
	if _, err := notes.ComputeTOTPCodeAt("!!!NOT_BASE32!!!", time.Now()); err == nil {
		t.Fatalf("expected invalid base32 secret to fail")
	}
	if ok, _ := notes.VerifyTOTPCodeAt("JBSWY3DPEHPK3PXP", "12", time.Now()); ok {
		t.Fatalf("expected short TOTP code to fail")
	}
	if codes, _, err := notes.GenerateBackupCodes(0); err != nil || len(codes) != 8 {
		t.Fatalf("expected default 8 backup codes")
	}
	if _, err := notes.SealExpressEnvelope("not-pem", "@a", "sub", []byte("hi")); err == nil {
		t.Fatalf("expected invalid PEM to fail SealExpressEnvelope")
	}
	if _, err := notes.UnsealExpressEnvelope("not-pem", notes.ExpressEnvelope{}); err == nil {
		t.Fatalf("expected invalid PEM to fail UnsealExpressEnvelope")
	}
	if _, _, err := notes.CreateWritttPack("pack", "", nil); err == nil {
		t.Fatalf("expected empty passphrase to fail")
	}
	if _, _, err := notes.ParseWritttPack([]byte("not-a-zip"), "pw"); err == nil {
		t.Fatalf("expected invalid zip to fail")
	}
}

