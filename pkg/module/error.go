package module

type SimpleError struct {
	Message string
}

func (e *SimpleError) Error() string {
	return e.Message
}

func MakeSimpleError(message string) error {
	return &SimpleError{
		Message: message,
	}
}
