package suite

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marcelomatz/matz-core/filestore"
)

// ProductID identifies an application in the Matz Suite.
type ProductID string

const (
	ProductMatz   ProductID = "matz"
	ProductHeapi  ProductID = "heapi"
	ProductMyTerm ProductID = "myterm"
	ProductWrittt ProductID = "writtt"
	ProductByCode ProductID = "bycode"
	ProductAdmin  ProductID = "matz-admin"
)

// FindWorkspaceRoot resolves the Matz Ecosystem workspace directory (preferring D:\MATZ).
func FindWorkspaceRoot() string {
	for _, candidate := range []string{`D:\MATZ`, `D:\Writtt`} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return filepath.Dir(wd)
	}
	return "."
}

// SuiteConfig holds user-level settings shared across all Matz Suite desktop apps.
type SuiteConfig struct {
	Theme          string            `yaml:"theme" json:"theme"`                     // "dark", "light", or custom theme name
	Locale         string            `yaml:"locale" json:"locale"`                   // "pt" or "en"
	DefaultShell   string            `yaml:"default_shell" json:"default_shell"`     // preferred PTY shell
	OllamaHost     string            `yaml:"ollama_host" json:"ollama_host"`         // default "http://127.0.0.1:11434"
	InstalledPaths map[string]string `yaml:"installed_paths" json:"installed_paths"` // productID -> executable path
}

// UpdateInfo describes whether a newer GitHub Release exists for a product.
type UpdateInfo struct {
	HasUpdate bool   `json:"hasUpdate"`
	Version   string `json:"version"`
	URL       string `json:"url"`
}

// GetSuiteDir returns ~/.matz (creating it if necessary).
func GetSuiteDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".matz")
	_ = os.MkdirAll(dir, 0700)
	_ = os.MkdirAll(filepath.Join(dir, "themes"), 0700)
	return dir
}

// LoadSuiteConfig loads ~/.matz/config.yaml or returns defaults.
func LoadSuiteConfig() SuiteConfig {
	cfg := SuiteConfig{
		Theme:          "dark",
		Locale:         "pt",
		OllamaHost:     "http://127.0.0.1:11434",
		InstalledPaths: make(map[string]string),
	}
	path := filepath.Join(GetSuiteDir(), "config.yaml")
	_ = filestore.ReadYAML(path, &cfg)
	if cfg.InstalledPaths == nil {
		cfg.InstalledPaths = make(map[string]string)
	}
	return cfg
}

// SaveSuiteConfig atomically persists ~/.matz/config.yaml.
func SaveSuiteConfig(cfg SuiteConfig) error {
	path := filepath.Join(GetSuiteDir(), "config.yaml")
	return filestore.WriteYAMLAtomic(path, cfg, 0600)
}

// RegisterCurrentApp records the current executable path in ~/.matz/config.yaml
// so other Matz Suite apps can discover and launch it via the App Switcher.
func RegisterCurrentApp(product ProductID) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	cfg := LoadSuiteConfig()
	cfg.InstalledPaths[string(product)] = exe
	_ = SaveSuiteConfig(cfg)
}

// LaunchSuiteApp launches another Matz Suite desktop application if installed locally.
func LaunchSuiteApp(product ProductID, args ...string) error {
	cfg := LoadSuiteConfig()
	if exe, ok := cfg.InstalledPaths[string(product)]; ok && exe != "" {
		if _, err := os.Stat(exe); err == nil {
			cmd := exec.Command(exe, args...)
			return cmd.Start()
		}
	}

	// Fallback 1: check known Matz Workspace binary locations in D:\MATZ / D:\Writtt
	wsRoot := FindWorkspaceRoot()
	workspaceBins := map[ProductID][]string{
		ProductMatz:   {filepath.Join(wsRoot, "matz-hub", "matz-hub.exe"), filepath.Join(wsRoot, "matz-hub", "build", "bin", "matz-hub.exe")},
		ProductHeapi:  {filepath.Join(wsRoot, "Heapi", "heapi.exe"), filepath.Join(wsRoot, "Heapi", "build", "bin", "heapi.exe")},
		ProductMyTerm: {filepath.Join(wsRoot, "myterm", "myterm.exe"), filepath.Join(wsRoot, "myterm", "build", "bin", "myterm.exe")},
		ProductWrittt: {filepath.Join(wsRoot, "writtt", "writtt.exe"), filepath.Join(wsRoot, "writtt", "build", "bin", "writtt.exe")},
		ProductByCode: {filepath.Join(wsRoot, "bycode", "byCode.exe"), filepath.Join(wsRoot, "bycode", "build", "bin", "byCode.exe")},
	}
	if paths, ok := workspaceBins[product]; ok {
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				cmd := exec.Command(p, args...)
				cmd.Dir = filepath.Dir(p)
				return cmd.Start()
			}
		}
	}

	// Fallback 2: look in sibling workspace build directories or PATH
	candidates := []string{string(product)}
	if runtime.GOOS == "windows" {
		candidates = append([]string{string(product) + ".exe"}, candidates...)
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			cmd := exec.Command(path, args...)
			return cmd.Start()
		}
	}
	return fmt.Errorf("aplicativo %s não encontrado localmente", product)
}

// CheckGitHubUpdate checks the latest GitHub release for a repository (e.g. "marcelomatz/myterm").
func CheckGitHubUpdate(repo, currentVersion, fallbackURL string) UpdateInfo {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return UpdateInfo{}
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "matz-suite/"+currentVersion)

	resp, err := client.Do(req)
	if err != nil {
		return UpdateInfo{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UpdateInfo{}
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return UpdateInfo{}
	}

	latest := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	current := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	url := release.HTMLURL
	if fallbackURL != "" {
		url = fallbackURL
	}

	return UpdateInfo{
		HasUpdate: latest != "" && latest != current && current != "dev" && current != "0.0.0",
		Version:   release.TagName,
		URL:       url,
	}
}
