package apperr

import "fmt"

const (
	ExitOK         = 0
	ExitGeneral    = 1
	ExitUsage      = 2
	ExitValidation = 3
	ExitTransport  = 4
	ExitHTTP       = 5
	ExitAuth       = 6
	ExitIntegrity  = 7
)

type Error struct {
	Code    int
	Kind    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Kind
}

func (e *Error) Unwrap() error { return e.Cause }

func New(code int, kind, message string) error {
	return &Error{Code: code, Kind: kind, Message: message}
}

func Wrap(code int, kind, message string, cause error) error {
	if cause == nil {
		return New(code, kind, message)
	}
	if message == "" {
		message = fmt.Sprintf("%s: %v", kind, cause)
	}
	return &Error{Code: code, Kind: kind, Message: message, Cause: cause}
}

func Code(err error) int {
	for err != nil {
		if typed, ok := err.(*Error); ok {
			if typed.Code > 0 {
				return typed.Code
			}
			err = typed.Cause
			continue
		}
		break
	}
	return ExitGeneral
}
