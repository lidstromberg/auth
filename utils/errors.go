package utils

import "errors"

var (
	//ErrCredentialsNotCorrect invalid credentials message
	ErrCredentialsNotCorrect = errors.New("supplied credentials cannot be verified")
)
