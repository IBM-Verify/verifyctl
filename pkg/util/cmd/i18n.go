package cmd

import "github.com/ibm-security-verify/verifyctl/pkg/i18n"

// TranslateLongDesc uses the prefix to construct a message code '<prefix>LongDesc'
// and looks for the value in the locale files. If not found, it falls back
// to the default text provided.
func TranslateLongDesc(prefix string, defaultText string) string {
	return i18n.TranslateWithCode(prefix+"LongDesc", defaultText)
}

// TranslateShortDesc uses the prefix to construct a message code '<prefix>ShortDesc'
// and looks for the value in the locale files. If not found, it falls back
// to the default text provided.
func TranslateShortDesc(prefix string, defaultText string) string {
	return i18n.TranslateWithCode(prefix+"ShortDesc", defaultText)
}

// TranslateExamples uses the prefix to construct a message code '<prefix>Examples'
// and looks for the value in the locale files. If not found, it falls back
// to the default text provided.
func TranslateExamples(prefix string, defaultText string) string {
	return i18n.TranslateWithCode(prefix+"Examples", defaultText)
}
