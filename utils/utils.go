package utils

import (
	"regexp"

	"github.com/segmentio/ksuid"
)

//NewID returns a new ID from ksuid
func NewID() string {
	return ksuid.New().String()
}

//NewIDs returns n new IDs from ksuid
func NewIDs(n int) []string {
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, NewID())
	}
	return ids
}

//EmailIsValid checks the email string
func EmailIsValid(emailAddress string) bool {
	//if the email is empty then reject
	if emailAddress == "" {
		return false
	}

	//from http://regexlib.com/REDetails.aspx?regexp_id=26
	var validEmail = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$`)

	//reject if this is an invalid email
	return validEmail.MatchString(emailAddress)
}
