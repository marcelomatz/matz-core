package terminal

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DetectShells returns the list of available shell binaries on this system.
func DetectShells() []string {
	var shells []string
	switch runtime.GOOS {
	case "windows":
		pathCandidates := []string{"pwsh.exe", "powershell.exe", "cmd.exe", "wsl.exe"}
		for _, c := range pathCandidates {
			if _, err := exec.LookPath(c); err == nil {
				shells = append(shells, c)
			}
		}
		bashPaths := []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
			`C:\msys64\usr\bin\bash.exe`,
			`C:\cygwin64\bin\bash.exe`,
		}
		if pf := os.Getenv("PROGRAMFILES"); pf != "" {
			bashPaths = append([]string{pf + `\Git\bin\bash.exe`}, bashPaths...)
		}
		for _, p := range bashPaths {
			if _, err := os.Stat(p); err == nil {
				shells = append(shells, p)
				break
			}
		}
	default:
		candidates := []string{"/bin/zsh", "/bin/bash", "/bin/sh", "/usr/bin/fish"}
		if s := os.Getenv("SHELL"); s != "" {
			found := false
			for _, c := range candidates {
				if c == s {
					found = true
					break
				}
			}
			if !found {
				candidates = append([]string{s}, candidates...)
			}
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				shells = append(shells, c)
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

// BestShell detects the preferred shell binary for the current OS.
func BestShell() string {
	return DetectShells()[0]
}

// ShellArgs returns extra startup arguments for well-known shells.
func ShellArgs(shell string) []string {
	lower := strings.ToLower(shell)
	switch {
	case strings.HasSuffix(lower, "powershell.exe"), strings.HasSuffix(lower, "pwsh.exe"), lower == "powershell", lower == "pwsh":
		return []string{"-NoLogo"}
	case strings.HasSuffix(lower, `\bash.exe`), strings.HasSuffix(lower, `/bash`):
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
	allowed := DetectShells()
	for _, a := range allowed {
		if strings.EqualFold(a, shell) {
			return true
		}
		if runtime.GOOS == "windows" && strings.EqualFold(a, shell+".exe") {
			return true
		}
	}
	return false
}
