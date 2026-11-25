package terminal

import (
	"testing"
)

func TestDetectShellsAndBestShell(t *testing.T) {
	shells := DetectShells()
	if len(shells) == 0 {
		t.Fatal("expected at least one shell detected")
	}
	best := BestShell()
	if best == "" {
		t.Fatal("expected non-empty BestShell")
	}
	if !IsAllowedShell(best) {
		t.Fatalf("expected BestShell %q to be allowed", best)
	}
	if !IsAllowedShell("") {
		t.Fatal("expected empty shell to be allowed")
	}
	args := ShellArgs("C:\\Program Files\\Git\\bin\\bash.exe")
	if len(args) != 2 || args[0] != "--login" {
		t.Fatalf("expected --login -i for bash.exe, got %v", args)
	}
	psArgs := ShellArgs("powershell.exe")
	if len(psArgs) != 1 || psArgs[0] != "-NoLogo" {
		t.Fatalf("expected -NoLogo for powershell.exe, got %v", psArgs)
	}
}
