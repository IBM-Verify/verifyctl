package i18n

type TextCode string

const (
	RootLongDesc  TextCode = "RootLongDesc"
	AuthShortDesc TextCode = "AuthShortDesc"
	AuthLongDesc  TextCode = "AuthLongDesc"
	AuthExamples  TextCode = "AuthExamples"
)

func TranslateWithCode(code TextCode, defaultText string) string {
	return defaultText
}

func Translate(text string) string {
	return text
}
