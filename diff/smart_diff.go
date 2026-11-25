package diff

import (
	"fmt"
	"regexp"
	"strings"
)

// SmartPatchBlock representa um bloco cirúrgico SEARCH/REPLACE gerado por um agente IA.
type SmartPatchBlock struct {
	Search  string `json:"search"`
	Replace string `json:"replace"`
}

// SmartPatchResult representa o resultado da aplicação de um patch cirúrgico em 4 níveis.
type SmartPatchResult struct {
	Success      bool   `json:"success"`
	Result       string `json:"result"`
	Error        string `json:"error,omitempty"`
	StrategyUsed string `json:"strategyUsed,omitempty"` // "exact", "whitespace", "line_trimmed", "anchor"
	LinesChanged int    `json:"linesChanged"`
}

var (
	smartPatchRe     = regexp.MustCompile(`(?s)<{3,7}\s*SEARCH\r?\n(.*?)\r?\n={3,7}\r?\n(.*?)\r?\n>{3,7}\s*REPLACE`)
	thoughtProcessRe = regexp.MustCompile(`(?is)<thought_process>.*?</thought_process>|<think>.*?</think>|<thinking>.*?</thinking>|<\|channel\|?>thought.*?<channel\|?>`)
)

// StripThinkingBlocks remove blocos de raciocínio (<thought_process>, <think>, <thinking>) de respostas de LLMs.
func StripThinkingBlocks(raw string) string {
	return strings.TrimSpace(thoughtProcessRe.ReplaceAllString(raw, ""))
}

// ParseSmartPatchBlocks extrai todos os blocos <<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE de um conteúdo.
func ParseSmartPatchBlocks(content string) []SmartPatchBlock {
	matches := smartPatchRe.FindAllStringSubmatch(content, -1)
	var out []SmartPatchBlock
	for _, m := range matches {
		if len(m) >= 3 {
			out = append(out, SmartPatchBlock{
				Search:  m[1],
				Replace: m[2],
			})
		}
	}
	return out
}

// ApplySmartPatch aplica um bloco SEARCH/REPLACE usando cascata de 4 níveis:
// 1. Exact Match
// 2. Whitespace-Normalized Match (CRLF/LF e espaços à direita)
// 3. Line-by-Line Trimmed Match (ignora indentação divergente e linhas em branco extras)
// 4. Anchor Match (primeiras 2 + últimas 2 linhas não-vazias quando o LLM omite o miolo com // ...)
func ApplySmartPatch(originalContent, search, replace string) SmartPatchResult {
	origNorm := strings.ReplaceAll(originalContent, "\r\n", "\n")
	searchNorm := strings.ReplaceAll(search, "\r\n", "\n")
	replaceNorm := strings.ReplaceAll(replace, "\r\n", "\n")

	// Nível 1: Exact Match
	if idx := strings.Index(origNorm, searchNorm); idx != -1 {
		res := origNorm[:idx] + replaceNorm + origNorm[idx+len(searchNorm):]
		return SmartPatchResult{
			Success:      true,
			Result:       res,
			StrategyUsed: "exact",
			LinesChanged: countLines(replaceNorm) - countLines(searchNorm),
		}
	}

	// Nível 2: Whitespace-Normalized Match (trimEnd por linha)
	if res, ok := applyPatchWhitespaceNormalized(origNorm, searchNorm, replaceNorm); ok {
		return res
	}

	// Nível 3: Line-by-Line Trimmed Match
	if res, ok := applyPatchByTrimmedLines(origNorm, searchNorm, replaceNorm); ok {
		return res
	}

	// Nível 4: Anchor Match (primeiras 2 e últimas 2 linhas não vazias)
	if res, ok := applyPatchByAnchors(origNorm, searchNorm, replaceNorm); ok {
		return res
	}

	return SmartPatchResult{
		Success:      false,
		Result:       originalContent,
		Error:        "SEARCH block not found in file after 4-level cascade (exact, whitespace, line_trimmed, anchor)",
		LinesChanged: 0,
	}
}

// ApplySmartPatches aplica múltiplos blocos SEARCH/REPLACE sequencialmente.
func ApplySmartPatches(originalContent string, patches []SmartPatchBlock) SmartPatchResult {
	current := originalContent
	totalChanged := 0
	lastStrategy := "exact"

	for i, p := range patches {
		res := ApplySmartPatch(current, p.Search, p.Replace)
		if !res.Success {
			return SmartPatchResult{
				Success:      false,
				Result:       current,
				Error:        fmt.Sprintf("patch %d/%d failed: %s", i+1, len(patches), res.Error),
				LinesChanged: totalChanged,
			}
		}
		current = res.Result
		totalChanged += res.LinesChanged
		lastStrategy = res.StrategyUsed
	}

	return SmartPatchResult{
		Success:      true,
		Result:       current,
		StrategyUsed: lastStrategy,
		LinesChanged: totalChanged,
	}
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

func applyPatchWhitespaceNormalized(orig, search, replace string) (SmartPatchResult, bool) {
	origLines := strings.Split(orig, "\n")
	searchLines := strings.Split(search, "\n")
	if len(searchLines) == 0 || len(origLines) < len(searchLines) {
		return SmartPatchResult{}, false
	}

	for i := 0; i <= len(origLines)-len(searchLines); i++ {
		match := true
		for j := 0; j < len(searchLines); j++ {
			if strings.TrimRight(origLines[i+j], " \t") != strings.TrimRight(searchLines[j], " \t") {
				match = false
				break
			}
		}
		if match {
			before := origLines[:i]
			after := origLines[i+len(searchLines):]
			combined := make([]string, 0, len(before)+1+len(after))
			combined = append(combined, before...)
			combined = append(combined, replace)
			combined = append(combined, after...)
			return SmartPatchResult{
				Success:      true,
				Result:       strings.Join(combined, "\n"),
				StrategyUsed: "whitespace",
				LinesChanged: countLines(replace) - len(searchLines),
			}, true
		}
	}
	return SmartPatchResult{}, false
}

type indexedLine struct {
	idx  int
	text string
}

func applyPatchByTrimmedLines(orig, search, replace string) (SmartPatchResult, bool) {
	origLines := strings.Split(orig, "\n")
	var searchTrimmed []string
	for _, l := range strings.Split(search, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			searchTrimmed = append(searchTrimmed, t)
		}
	}
	if len(searchTrimmed) == 0 {
		return SmartPatchResult{}, false
	}

	var origNonEmpty []indexedLine
	for i, l := range origLines {
		if t := strings.TrimSpace(l); t != "" {
			origNonEmpty = append(origNonEmpty, indexedLine{idx: i, text: t})
		}
	}
	if len(origNonEmpty) < len(searchTrimmed) {
		return SmartPatchResult{}, false
	}

	for i := 0; i <= len(origNonEmpty)-len(searchTrimmed); i++ {
		match := true
		for j := 0; j < len(searchTrimmed); j++ {
			if origNonEmpty[i+j].text != searchTrimmed[j] {
				match = false
				break
			}
		}
		if match {
			startIdx := origNonEmpty[i].idx
			endIdx := origNonEmpty[i+len(searchTrimmed)-1].idx
			before := origLines[:startIdx]
			after := origLines[endIdx+1:]
			combined := make([]string, 0, len(before)+1+len(after))
			combined = append(combined, before...)
			combined = append(combined, replace)
			combined = append(combined, after...)
			return SmartPatchResult{
				Success:      true,
				Result:       strings.Join(combined, "\n"),
				StrategyUsed: "line_trimmed",
				LinesChanged: countLines(replace) - (endIdx - startIdx + 1),
			}, true
		}
	}
	return SmartPatchResult{}, false
}

func applyPatchByAnchors(orig, search, replace string) (SmartPatchResult, bool) {
	var searchTrimmed []string
	for _, l := range strings.Split(search, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			searchTrimmed = append(searchTrimmed, t)
		}
	}
	if len(searchTrimmed) < 4 {
		return SmartPatchResult{}, false
	}

	origLines := strings.Split(orig, "\n")
	origTrimmed := make([]string, len(origLines))
	for i, l := range origLines {
		origTrimmed[i] = strings.TrimSpace(l)
	}

	startAnchor0, startAnchor1 := searchTrimmed[0], searchTrimmed[1]
	endAnchor0, endAnchor1 := searchTrimmed[len(searchTrimmed)-2], searchTrimmed[len(searchTrimmed)-1]

	startIdx := -1
	for i := 0; i <= len(origTrimmed)-2; i++ {
		if origTrimmed[i] == startAnchor0 && origTrimmed[i+1] == startAnchor1 {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return SmartPatchResult{}, false
	}

	endIdx := -1
	for i := startIdx + 1; i <= len(origTrimmed)-2; i++ {
		if origTrimmed[i] == endAnchor0 && origTrimmed[i+1] == endAnchor1 {
			endIdx = i + 1
			break
		}
	}
	if endIdx == -1 {
		return SmartPatchResult{}, false
	}

	before := origLines[:startIdx]
	after := origLines[endIdx+1:]
	combined := make([]string, 0, len(before)+1+len(after))
	combined = append(combined, before...)
	combined = append(combined, replace)
	combined = append(combined, after...)

	return SmartPatchResult{
		Success:      true,
		Result:       strings.Join(combined, "\n"),
		StrategyUsed: "anchor",
		LinesChanged: countLines(replace) - (endIdx - startIdx + 1),
	}, true
}
