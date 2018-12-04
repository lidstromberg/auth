package utils

import (
	"context"
	"regexp"

	"cloud.google.com/go/datastore"
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

//NewDsKey is datastore specific and returns a key using datastore.AllocateIDs
func NewDsKey(ctx context.Context, dsClient *datastore.Client, dsNS, dsKind string) (*datastore.Key, error) {
	var keys []*datastore.Key

	//create an incomplete key of the type and namespace
	newKey := datastore.IncompleteKey(dsKind, nil)
	newKey.Namespace = dsNS

	//append it to the slice
	keys = append(keys, newKey)

	//allocate the ID from datastore
	keys, err := dsClient.AllocateIDs(ctx, keys)

	if err != nil {
		return nil, err
	}

	//return only the first key
	return keys[0], nil
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
