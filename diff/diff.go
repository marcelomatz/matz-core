// Package diff implementa análise estruturada de Unified Diffs (git diff) e cálculo de diff em memória (LCS)
// para todos os aplicativos Go da suíte MATZ (Matz Hub, byCode, Heapi, myTerm e Writtt).
package diff

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// LineKind identifica o tipo de linha em um diff.
type LineKind string

const (
	LineContext LineKind = "context"
	LineAdd     LineKind = "add"
	LineDel     LineKind = "del"
	LineHunk    LineKind = "hunk"
)

// DiffLine representa uma linha individual numerada em um Hunk ou comparador LCS.
type DiffLine struct {
	Kind    LineKind `json:"kind"`
	OldLine int      `json:"oldLine,omitempty"`
	NewLine int      `json:"newLine,omitempty"`
	Content string   `json:"content"`
}

// DiffHunk representa um bloco @@ -a,b +c,d @@ dentro de um arquivo modificado.
type DiffHunk struct {
	Header   string     `json:"header"`
	OldStart int        `json:"oldStart"`
	OldCount int        `json:"oldCount"`
	NewStart int        `json:"newStart"`
	NewCount int        `json:"newCount"`
	Lines    []DiffLine `json:"lines"`
}

// DiffFile representa as alterações de um único arquivo dentro de um patch multi-arquivo.
type DiffFile struct {
	OldPath   string     `json:"oldPath"`
	NewPath   string     `json:"newPath"`
	Status    string     `json:"status"` // "modified" | "added" | "deleted" | "renamed"
	Additions int        `json:"additions"`
	Deletions int        `json:"deletions"`
	Hunks     []DiffHunk `json:"hunks"`
}

// DiffSummary agrega todos os arquivos e estatísticas de um patch Git.
type DiffSummary struct {
	Files          []DiffFile `json:"files"`
	TotalFiles     int        `json:"totalFiles"`
	TotalAdditions int        `json:"totalAdditions"`
	TotalDeletions int        `json:"totalDeletions"`
}

var hunkHeaderRegex = regexp.MustCompile(`^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$`)

// ParseUnifiedDiff analisa um patch Unified Diff (git diff) em arquivos, hunks e linhas numeradas.
func ParseUnifiedDiff(raw string) DiffSummary {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")

	var files []DiffFile
	var curFile *DiffFile
	var curHunk *DiffHunk
	oldLn := 0
	newLn := 0

	flushHunk := func() {
		if curFile != nil && curHunk != nil {
			curFile.Hunks = append(curFile.Hunks, *curHunk)
			curHunk = nil
		}
	}
	flushFile := func() {
		flushHunk()
		if curFile != nil {
			files = append(files, *curFile)
			curFile = nil
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			flushFile()
			parts := strings.Fields(line)
			oldP, newP := "arquivo", "arquivo"
			if len(parts) >= 4 {
				oldP = strings.TrimPrefix(parts[2], "a/")
				newP = strings.TrimPrefix(parts[3], "b/")
			}
			curFile = &DiffFile{
				OldPath: oldP,
				NewPath: newP,
				Status:  "modified",
			}
			continue
		}

		if curFile == nil {
			if strings.HasPrefix(line, "--- ") {
				oldP := strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "--- ")), "a/")
				curFile = &DiffFile{OldPath: oldP, NewPath: oldP, Status: "modified"}
				continue
			}
			if m := hunkHeaderRegex.FindStringSubmatch(line); len(m) > 0 {
				curFile = &DiffFile{OldPath: "patch", NewPath: "patch", Status: "modified"}
			} else {
				continue
			}
		}

		if strings.HasPrefix(line, "new file mode") {
			curFile.Status = "added"
			continue
		}
		if strings.HasPrefix(line, "deleted file mode") {
			curFile.Status = "deleted"
			continue
		}
		if strings.HasPrefix(line, "rename from ") {
			curFile.Status = "renamed"
			curFile.OldPath = strings.TrimSpace(strings.TrimPrefix(line, "rename from "))
			continue
		}
		if strings.HasPrefix(line, "rename to ") {
			curFile.Status = "renamed"
			curFile.NewPath = strings.TrimSpace(strings.TrimPrefix(line, "rename to "))
			continue
		}
		if strings.HasPrefix(line, "--- ") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "--- "))
			if p != "/dev/null" {
				curFile.OldPath = strings.TrimPrefix(p, "a/")
			} else {
				curFile.Status = "added"
			}
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			if p != "/dev/null" {
				curFile.NewPath = strings.TrimPrefix(p, "b/")
			} else {
				curFile.Status = "deleted"
			}
			continue
		}

		if m := hunkHeaderRegex.FindStringSubmatch(line); len(m) > 0 {
			flushHunk()
			oStart, _ := strconv.Atoi(m[1])
			oCount := 1
			if m[2] != "" {
				oCount, _ = strconv.Atoi(m[2])
			}
			nStart, _ := strconv.Atoi(m[3])
			nCount := 1
			if m[4] != "" {
				nCount, _ = strconv.Atoi(m[4])
			}
			oldLn = oStart
			newLn = nStart
			curHunk = &DiffHunk{
				Header:   line,
				OldStart: oStart,
				OldCount: oCount,
				NewStart: nStart,
				NewCount: nCount,
			}
			continue
		}

		if curHunk != nil {
			if strings.HasPrefix(line, "+") {
				curFile.Additions++
				curHunk.Lines = append(curHunk.Lines, DiffLine{
					Kind:    LineAdd,
					NewLine: newLn,
					Content: line[1:],
				})
				newLn++
			} else if strings.HasPrefix(line, "-") {
				curFile.Deletions++
				curHunk.Lines = append(curHunk.Lines, DiffLine{
					Kind:    LineDel,
					OldLine: oldLn,
					Content: line[1:],
				})
				oldLn++
			} else if strings.HasPrefix(line, " ") || line == "" {
				content := line
				if len(line) > 0 {
					content = line[1:]
				}
				curHunk.Lines = append(curHunk.Lines, DiffLine{
					Kind:    LineContext,
					OldLine: oldLn,
					NewLine: newLn,
					Content: content,
				})
				oldLn++
				newLn++
			}
		}
	}

	flushFile()

	totalAdd, totalDel := 0, 0
	for _, f := range files {
		totalAdd += f.Additions
		totalDel += f.Deletions
	}

	return DiffSummary{
		Files:          files,
		TotalFiles:     len(files),
		TotalAdditions: totalAdd,
		TotalDeletions: totalDel,
	}
}

// ComputeLineDiff calcula o diff linha-a-linha entre dois textos usando programação dinâmica LCS.
func ComputeLineDiff(oldText, newText string) []DiffLine {
	oldText = strings.ReplaceAll(oldText, "\r\n", "\n")
	newText = strings.ReplaceAll(newText, "\r\n", "\n")

	var oldLines, newLines []string
	if oldText != "" {
		oldLines = strings.Split(oldText, "\n")
	}
	if newText != "" {
		newLines = strings.Split(newText, "\n")
	}

	m, n := len(oldLines), len(newLines)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = 1 + dp[i+1][j+1]
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var result []DiffLine
	i, j := 0, 0
	oldNum, newNum := 1, 1
	for i < m && j < n {
		if oldLines[i] == newLines[j] {
			result = append(result, DiffLine{
				Kind:    LineContext,
				OldLine: oldNum,
				NewLine: newNum,
				Content: oldLines[i],
			})
			i++
			j++
			oldNum++
			newNum++
		} else if dp[i+1][j] >= dp[i][j+1] {
			result = append(result, DiffLine{
				Kind:    LineDel,
				OldLine: oldNum,
				Content: oldLines[i],
			})
			i++
			oldNum++
		} else {
			result = append(result, DiffLine{
				Kind:    LineAdd,
				NewLine: newNum,
				Content: newLines[j],
			})
			j++
			newNum++
		}
	}
	for i < m {
		result = append(result, DiffLine{
			Kind:    LineDel,
			OldLine: oldNum,
			Content: oldLines[i],
		})
		i++
		oldNum++
	}
	for j < n {
		result = append(result, DiffLine{
			Kind:    LineAdd,
			NewLine: newNum,
			Content: newLines[j],
		})
		j++
		newNum++
	}
	return result
}

// FormatUnifiedPatch gera uma representação Unified Diff a partir de dois textos em memória.
func FormatUnifiedPatch(fileName, oldText, newText string) string {
	lines := ComputeLineDiff(oldText, newText)
	if len(lines) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1,%d +1,%d @@\n",
		fileName, fileName, fileName, fileName, len(lines), len(lines)))
	for _, l := range lines {
		switch l.Kind {
		case LineAdd:
			sb.WriteString("+" + l.Content + "\n")
		case LineDel:
			sb.WriteString("-" + l.Content + "\n")
		default:
			sb.WriteString(" " + l.Content + "\n")
		}
	}
	return sb.String()
}
