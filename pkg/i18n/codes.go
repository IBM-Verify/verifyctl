package i18n

type TextCode string

const (
	RootLongDesc   TextCode = "RootLongDesc"
	LoginShortDesc TextCode = "LoginShortDesc"
	LoginLongDesc  TextCode = "LoginLongDesc"
	LoginExamples  TextCode = "LoginExamples"
)

func TranslateWithCode(code TextCode, defaultText string) string {
	return defaultText
}

func Translate(text string) string {
	return text
}
