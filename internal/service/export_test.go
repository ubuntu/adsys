package service

import (
	"errors"
)

func FailingOption() func(o *options) error {
	return func(o *options) error {
		return errors.New("failing option")
	}
}
