package core_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/marcelomatz/matz-core/filestore"
	"github.com/marcelomatz/matz-core/httpengine"
	"github.com/marcelomatz/matz-core/notes"
	"github.com/marcelomatz/matz-core/sqlite"
	"github.com/marcelomatz/matz-core/terminal"
)

func TestFileStoreAtomicAndSQLiteWAL(t *testing.T) {
	tmp := t.TempDir()
	yamlPath := filepath.Join(tmp, "sample.yaml")

	payload := map[string]string{"hello": "matz"}
	if err := filestore.WriteYAMLAtomic(yamlPath, payload, 0600); err != nil {
		t.Fatalf("WriteYAMLAtomic failed: %v", err)
	}

	var out map[string]string
	if err := filestore.ReadYAML(yamlPath, &out); err != nil {
		t.Fatalf("ReadYAML failed: %v", err)
	}
	if out["hello"] != "matz" {
		t.Fatalf("expected matz, got %q", out["hello"])
	}

	db, err := sqlite.OpenWAL(filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow("PRAGMA journal_mode;").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("expected wal mode, got %s", mode)
	}
}

func TestHTTPEngineAndNotesCrypto(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	eng := httpengine.NewEngine()
	res, err := eng.Execute(
		"req-1",
		"GET",
		"{{base}}/check",
		"[]",
		"",
		`{"type":"apikey","apiKey":"X-API-Key","apiValue":"{{key}}","apiIn":"header"}`,
		map[string]string{"base": srv.URL, "key": "secret-123"},
	)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if res.StatusCode != 200 || res.Body != `{"ok":true}` {
		t.Fatalf("unexpected response: %+v", res)
	}

	enc, err := notes.Encrypt("master-pass", []byte("Top secret note"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !notes.IsEncrypted(enc) {
		t.Fatalf("expected encrypted prefix")
	}
	dec, err := notes.Decrypt("master-pass", enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(dec) != "Top secret note" {
		t.Fatalf("unexpected decrypted text: %s", string(dec))
	}
}

func TestTerminalShellDetection(t *testing.T) {
	shells := terminal.DetectShells()
	if len(shells) == 0 {
		t.Fatalf("expected at least 1 detected shell")
	}
	if !terminal.IsAllowedShell(shells[0]) {
		t.Fatalf("expected first shell %q to be allowed", shells[0])
	}
}
