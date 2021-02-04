package decorate

import "fmt"

// OnError prefixes any error with format/args
func OnError(err *error, format string, args ...interface{}) {
	if *err != nil {
		s := fmt.Sprintf(format, args...)
		*err = fmt.Errorf("%s: %v", s, *err)
	}
}
