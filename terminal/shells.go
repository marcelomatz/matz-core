package terminal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DetectShells returns the list of available shell binaries on this system,
// ordered by developer preference (Git Bash, PowerShell 7, Windows PowerShell, CMD, etc.).
// On Windows, wsl.exe is only appended if a WSL distribution is actually installed.
func DetectShells() []string {
	var shells []string
	seen := make(map[string]bool)

	addShell := func(p string) {
		if p == "" {
			return
		}
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return
		}
		seen[key] = true
		shells = append(shells, p)
	}

	switch runtime.GOOS {
	case "windows":
		// 1. Git Bash (preferred POSIX shell on Windows)
		var bashPaths []string
		if pf := os.Getenv("PROGRAMFILES"); pf != "" {
			bashPaths = append(bashPaths, filepath.Join(pf, "Git", "bin", "bash.exe"))
			bashPaths = append(bashPaths, filepath.Join(pf, "Git", "usr", "bin", "bash.exe"))
		}
		if pfx86 := os.Getenv("PROGRAMFILES(X86)"); pfx86 != "" {
			bashPaths = append(bashPaths, filepath.Join(pfx86, "Git", "bin", "bash.exe"))
		}
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			bashPaths = append(bashPaths, filepath.Join(localApp, "Programs", "Git", "bin", "bash.exe"))
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			bashPaths = append(bashPaths, filepath.Join(home, "scoop", "apps", "git", "current", "bin", "bash.exe"))
		}
		bashPaths = append(bashPaths,
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
		)
		for _, p := range bashPaths {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				addShell(p)
				break
			}
		}

		// 2. PowerShell 7 (pwsh.exe), Windows PowerShell (powershell.exe), Command Prompt (cmd.exe)
		for _, c := range []string{"pwsh.exe", "powershell.exe", "cmd.exe"} {
			if path, err := exec.LookPath(c); err == nil {
				addShell(path)
			}
		}

		// 3. MSYS2 / Cygwin / NuShell if installed
		extraPaths := []string{
			`C:\msys64\usr\bin\bash.exe`,
			`C:\cygwin64\bin\bash.exe`,
		}
		for _, p := range extraPaths {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				addShell(p)
			}
		}
		if nuPath, err := exec.LookPath("nu.exe"); err == nil {
			addShell(nuPath)
		}

		// 4. WSL (only if a distribution is actually installed and ready)
		if wslPath, err := exec.LookPath("wsl.exe"); err == nil && hasInstalledWSLDistro() {
			addShell(wslPath)
		}

	default:
		if s := os.Getenv("SHELL"); s != "" {
			if info, err := os.Stat(s); err == nil && !info.IsDir() {
				addShell(s)
			}
		}
		candidates := []string{
			"/bin/zsh",
			"/usr/bin/zsh",
			"/bin/bash",
			"/usr/bin/bash",
			"/usr/bin/fish",
			"/usr/local/bin/fish",
			"/usr/local/bin/pwsh",
			"/usr/bin/pwsh",
			"/bin/sh",
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				addShell(c)
			}
		}
	}

	if len(shells) == 0 {
		if runtime.GOOS == "windows" {
			shells = []string{"powershell.exe"}
		} else {
			shells = []string{"/bin/sh"}
		}
	}
	return shells
}

// hasInstalledWSLDistro checks whether WSL has at least one registered Linux distribution
// without triggering any interactive installation prompt.
func hasInstalledWSLDistro() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	// Query Windows Registry for Lxss DefaultDistribution or subkeys via reg.exe
	cmd := exec.CommandContext(ctx, "reg.exe", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	text := string(out)
	return strings.Contains(text, "DefaultDistribution") || strings.Contains(text, `Lxss\{`)
}

// BestShell detects the preferred shell binary for the current OS.
func BestShell() string {
	return DetectShells()[0]
}

// ShellArgs returns extra startup arguments for well-known shells.
func ShellArgs(shell string) []string {
	lower := strings.ToLower(filepath.Base(shell))
	switch {
	case lower == "powershell.exe" || lower == "pwsh.exe" || lower == "powershell" || lower == "pwsh":
		return []string{"-NoLogo"}
	case lower == "bash.exe" || lower == "bash":
		return []string{"--login", "-i"}
	default:
		return nil
	}
}

// IsAllowedShell verifies if the requested shell is in DetectShells() (or empty for default).
func IsAllowedShell(shell string) bool {
	if shell == "" {
		return true
	}
	cleanReq := strings.ToLower(filepath.Clean(shell))
	baseReq := strings.ToLower(filepath.Base(shell))
	allowed := DetectShells()
	for _, a := range allowed {
		cleanAllowed := strings.ToLower(filepath.Clean(a))
		baseAllowed := strings.ToLower(filepath.Base(a))
		if cleanAllowed == cleanReq || baseAllowed == baseReq {
			return true
		}
		if runtime.GOOS == "windows" && (cleanAllowed == cleanReq+".exe" || baseAllowed == baseReq+".exe") {
			return true
		}
	}
	return false
}
