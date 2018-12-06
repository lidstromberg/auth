package auth

import "errors"

var (
	//ErrEmailInvalid email invalid message
	ErrEmailInvalid = errors.New("email is not valid")
	//ErrCredentialDataMgrInvalid type name is not valid message
	ErrCredentialDataMgrInvalid = errors.New("credential service type is not valid")
	//ErrCredentialsNotExist credentials not located message
	ErrCredentialsNotExist = errors.New("login credentials could not be located")
	//ErrAccountIsRegistered account already registered message
	ErrAccountIsRegistered = errors.New("account is already registered")
	//ErrAccountNotExist unregistered account message
	ErrAccountNotExist = errors.New("account is not registered")
	//ErrFailedToSave failed to save save error message
	ErrFailedToSave = errors.New("unable to save account data")
	//ErrAccountRegNotCompleted confirmation token generation failure message
	ErrAccountRegNotCompleted = errors.New("failed to generate account confirmation record")
	//ErrMailConfirmNotCompleted failed to send registration email message
	ErrMailConfirmNotCompleted = errors.New("failed to send confirmation email")
	//ErrConfirmTokenInvalid failed to send registration email message
	ErrConfirmTokenInvalid = errors.New("registration confirmation token is not valid, it may have expired or have been previously used")
	//ErrAccountNotLocated account not located message
	ErrAccountNotLocated = errors.New("account was not located")
	//ErrAccountIsLocked account has been locked message
	ErrAccountIsLocked = errors.New("account is locked - please try later")
	//ErrAccountCannotBeCreated failure to create account message
	ErrAccountCannotBeCreated = errors.New("could not create new account")
	//ErrAppRoleAccessDenied message shown when the jwt does not provide access to an application
	ErrAppRoleAccessDenied = errors.New("user does not have access to this application")
	//ErrAccountAppMappingNotExist account applications don't exist message
	ErrAccountAppMappingNotExist = errors.New("accountapplication mapping for this account does not exist")
	//ErrOtpNotExist message indicates a one time password was required but not supplied
	ErrOtpNotExist = errors.New("two factor authentication passcode was not supplied")
	//ErrSysDefNotExist message indicates a system default was not located
	ErrSysDefNotExist = errors.New("system default was not located")
	//ErrLcNotExist error message
	ErrLcNotExist = errors.New("the login candidate does not exist")
	//ErrLcExpired error message
	ErrLcExpired = errors.New("the login candidate has expired")
)
