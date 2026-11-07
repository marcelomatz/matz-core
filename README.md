# matz-core — Shared Go 1.27+ Native Engine for the MATZ Suite

Motor nativo em **Go 1.27.3** compartilhado por todos os aplicativos desktop e servidores do ecossistema **MATZ** (`Matz Hub`, `byCode IDE`, `Heapi`, `MyTerm` e `Writtt`).

## Módulos (`github.com/marcelomatz/matz-core`)
- `suite`: Descoberta de aplicativos da suíte, IPC local (`~/.matz/config.yaml`), App Switcher e verificador de atualizações via GitHub Releases.
- `terminal`: Gerenciador de sessões pseudo-terminal nativas (Windows ConPTY & Unix PTY).
- `httpengine`: Motor HTTP/REST com suporte a certificados mTLS (PEM e PKCS#12 `.p12`/`.pfx`), métricas de latência e redirecionamentos.
- `notes`: Cofre criptográfico Zero-Knowledge (`Argon2id` + `AES-256-GCM`) e indexador full-text Markdown.
- `sqlite`: Wrapper SQLite3 em modo `WAL` (Write-Ahead Logging) puro em Go (`modernc.org/sqlite`, zero CGO).
- `filestore`: Leitura e escrita atômica de arquivos YAML/JSON.
