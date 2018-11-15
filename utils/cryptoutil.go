package utils

import (
	"golang.org/x/crypto/bcrypt"
)

//GetStringHash hashes a plain text password string
func GetStringHash(inString string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(inString), 12)
	return string(bytes), err
}

//GetHashCompare compares a string with the password hash
func GetHashCompare(inString string, inCmpHash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(inString), []byte(inCmpHash))

	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, ErrCredentialsNotCorrect
		}
		return false, err
	}

	return true, err
}
