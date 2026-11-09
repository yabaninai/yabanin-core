package classifier

import (
	"regexp"
	"strings"
)

// Features represents extracted signals from a prompt that influence classification.
type Features struct {
	PromptTokens    int      // estimated token count (~4 chars = 1 token)
	HasCodeFence    bool     // presence of ``` code blocks
	CodeFenceLines  int      // total lines inside code fences
	HasToolCallJSON bool     // tool/function call patterns present
	KeywordsEasy    []string // detected easy-indicator keywords
	KeywordsHard    []string // detected hard-indicator keywords
	QuestionMarks   int      // number of question marks in prompt
	ContextTokens   int      // total tokens in context window (includes system prompt)
}

var (
	codeFenceRe  = regexp.MustCompile("(?s)```.*?```")
	easyKeywords = []string{
		"summarize", "summary", "translate", "extract", "classify",
		"list", "name", "what is", "define", "describe",
		"convert", "format", "rewrite", "rephrase",
	}
	hardKeywords = []string{
		"debug", "architect", "design", "reason step by step", "step-by-step",
		"analyze", "investigate", "optimize", "refactor", "implement complex",
		"write tests for", "code review", "troubleshoot",
	}
	toolCallRe = regexp.MustCompile(`"function"|"tool_calls"|"tools"\s*:`)
)

// ExtractFeatures extracts classification signals from the prompt input.
func ExtractFeatures(in Input) Features {
	fullText := strings.Join(in.Messages, "\n") + "\n" + in.Prompt
	lower := strings.ToLower(fullText)

	f := Features{
		PromptTokens:  len(fullText) / 4,
		QuestionMarks: strings.Count(fullText, "?"),
		ContextTokens: in.ContextTokens,
	}

	if matches := codeFenceRe.FindAllString(fullText, -1); len(matches) > 0 {
		f.HasCodeFence = true
		for _, m := range matches {
			f.CodeFenceLines += strings.Count(m, "\n")
		}
	}

	if toolCallRe.MatchString(fullText) {
		f.HasToolCallJSON = true
	}

	for _, kw := range easyKeywords {
		if strings.Contains(lower, kw) {
			f.KeywordsEasy = append(f.KeywordsEasy, kw)
		}
	}

	for _, kw := range hardKeywords {
		if strings.Contains(lower, kw) {
			f.KeywordsHard = append(f.KeywordsHard, kw)
		}
	}

	return f
}
