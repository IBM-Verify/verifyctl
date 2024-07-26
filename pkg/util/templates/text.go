package templates

import "strings"

const indentation = `  `

func LongDesc(s string) string {
	if len(s) == 0 {
		return s
	}

	return normalizer{s}.trim().string
}

func Examples(s string) string {
	if len(s) == 0 {
		return s
	}

	return normalizer{s}.trim().indent().string
}

// normalizer provides string utilities.
// It borrows heavily from kubectl.
type normalizer struct {
	string
}

func (n normalizer) trim() normalizer {
	n.string = strings.TrimSpace(n.string)
	return n
}

func (n normalizer) indent() normalizer {
	indentedLines := []string{}
	for _, line := range strings.Split(n.string, "\n") {
		trimmed := strings.TrimSpace(line)
		indented := indentation + trimmed
		indentedLines = append(indentedLines, indented)
	}

	n.string = strings.Join(indentedLines, "\n")
	return n
}
