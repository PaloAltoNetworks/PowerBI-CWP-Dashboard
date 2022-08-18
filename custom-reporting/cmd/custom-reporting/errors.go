package custom_reporting

import "github.com/sirupsen/logrus"

type GenericError struct {
	Msg string
}

func (e *GenericError) Error() string {
	logrus.Errorf(e.Msg)
	return e.Msg
}
