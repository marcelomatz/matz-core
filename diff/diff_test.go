package diff

import (
	"strings"
	"testing"
)

func TestParseUnifiedDiffAndComputeLineDiff(t *testing.T) {
	rawPatch := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -10,4 +10,5 @@ func main() {
 	app := NewApp()
-	app.RunLegacy()
+	app.EnableCOEAlgorithms()
+	app.Run()
 }
`
	summary := ParseUnifiedDiff(rawPatch)
	if summary.TotalFiles != 1 || summary.TotalAdditions != 2 || summary.TotalDeletions != 1 {
		t.Fatalf("estatisticas de diff inesperadas: %+v", summary)
	}
	if summary.Files[0].NewPath != "main.go" || len(summary.Files[0].Hunks) != 1 {
		t.Fatalf("arquivo/hunk inesperado: %+v", summary.Files[0])
	}

	lines := ComputeLineDiff("linha 1\nlinha antiga\nlinha 3", "linha 1\nlinha nova\nlinha 3")
	adds, dels := 0, 0
	for _, l := range lines {
		if l.Kind == LineAdd {
			adds++
		} else if l.Kind == LineDel {
			dels++
		}
	}
	if adds != 1 || dels != 1 {
		t.Fatalf("ComputeLineDiff deveria detectar 1 add e 1 del, obteve add=%d del=%d", adds, dels)
	}

	patch := FormatUnifiedPatch("README.md", "a\nb", "a\nc")
	if !strings.Contains(patch, "-b") || !strings.Contains(patch, "+c") {
		t.Fatalf("FormatUnifiedPatch invalido: %s", patch)
	}
}

func TestSmartDiffFourLevelCascade(t *testing.T) {
	original := "package main\n\nfunc calcular(x int) int {\n\ta := x * 2\n\tb := a + 10\n\tc := b - 3\n\treturn c\n}\n"

	// 1. Exact
	r1 := ApplySmartPatch(original, "\ta := x * 2", "\ta := x * 4")
	if !r1.Success || r1.StrategyUsed != "exact" || !strings.Contains(r1.Result, "x * 4") {
		t.Fatalf("falha no nivel 1 (exact): %+v", r1)
	}

	// 2. Whitespace-normalized (trailing spaces)
	r2 := ApplySmartPatch("linha1   \nlinha2\n", "linha1\nlinha2", "linhaNova")
	if !r2.Success || r2.StrategyUsed != "whitespace" || !strings.Contains(r2.Result, "linhaNova") {
		t.Fatalf("falha no nivel 2 (whitespace): %+v", r2)
	}

	// 3. Line-trimmed (diferenca de indentacao)
	r3 := ApplySmartPatch(original, "  a := x * 2\n  b := a + 10", "\ta := x * 8\n\tb := a + 20")
	if !r3.Success || r3.StrategyUsed != "line_trimmed" || !strings.Contains(r3.Result, "x * 8") {
		t.Fatalf("falha no nivel 3 (line_trimmed): %+v", r3)
	}

	// 4. Anchor match (LLM omitiu linhas intermediarias com // ...)
	r4 := ApplySmartPatch(
		original,
		"func calcular(x int) int {\n\ta := x * 2\n\t// ... omitido\n\tc := b - 3\n\treturn c",
		"func calcular(x int) int {\n\treturn x * 100",
	)
	if !r4.Success || r4.StrategyUsed != "anchor" || !strings.Contains(r4.Result, "return x * 100") {
		t.Fatalf("falha no nivel 4 (anchor): %+v", r4)
	}

	// ParseSmartPatchBlocks & StripThinkingBlocks
	rawLLM := "<think>pensando...</think>\n<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE"
	cleaned := StripThinkingBlocks(rawLLM)
	if strings.Contains(cleaned, "pensando") {
		t.Fatalf("StripThinkingBlocks nao removeu <think>: %s", cleaned)
	}
	blocks := ParseSmartPatchBlocks(cleaned)
	if len(blocks) != 1 || blocks[0].Search != "old" || blocks[0].Replace != "new" {
		t.Fatalf("ParseSmartPatchBlocks falhou: %+v", blocks)
	}
	multi := ApplySmartPatches("old\n", blocks)
	if !multi.Success || !strings.Contains(multi.Result, "new") {
		t.Fatalf("ApplySmartPatches falhou: %+v", multi)
	}
}
