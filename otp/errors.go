package otp

import "errors"

//ErrPasscodeNotValid invalid passcode message
var ErrPasscodeNotValid = errors.New("supplied passcode is not valid")
