package authcommon

import (
	"context"
)

//CredentialDataMgr covers the actions which a credential service should provide
type CredentialDataMgr interface {
	AccountMeta
	AccountUpdate
	SystemSetting
	GenAuthID
}

//AccountMeta defines operations to retrieve account metadata
type AccountMeta interface {
	GetAccountCredential(ctx context.Context, emailAddress string) (*UserAccountCredential, error)
	GetAccountCount(ctx context.Context, emailAddress string) (int, error)
	GetLoginProfile(ctx context.Context, userID string) (*UserAccount, error)
	GetLoginProfileByEmail(ctx context.Context, emailAddress string) (*UserAccount, error)
	GetAccountApp(ctx context.Context, userID string) ([]*UserAccountApplication, error)
	GetAccountConfirmation(ctx context.Context, userAccountToken string) (*UserAccountConfirmation, error)
}

//AccountUpdate defines operations to transform or change an account
type AccountUpdate interface {
	SavedFailedLogin(ctx context.Context, emailAddress string) error
	ResetFailedLogin(ctx context.Context, emailAddress string) error
	SaveAccount(ctx context.Context, userAccount *UserAccount) (string, error)
	StartAccountConfirmation(ctx context.Context, userID, emailAddress, userAccountConfirmationType, url, urlrd, sender, sendername string) (*UserEmailConfirm, error)
	SaveAccountConfirmation(ctx context.Context, userAccountConf *UserAccountConfirmation) (*UserAccountConfirmationResult, error)
}

//SystemSetting defines an operation to retrieve a system setting (key/value)
type SystemSetting interface {
	GetSystemDefault(ctx context.Context, systemKey string) (*SystemDefault, error)
	SaveSystemDefault(ctx context.Context, systemKey, systemVal string) error
}

//GenAuthID defines operations to create new entity ids
type GenAuthID interface {
	NewAccountID(ctx context.Context) (string, error)
	NewConfirmID(ctx context.Context) (string, error)
}

//CredentialDataMgrStore enum for credential services
type CredentialDataMgrStore int

//Datastore defines the types of available CredentialDataMgrStore
const (
	Datastore = CredentialDataMgrStore(iota)
	PostgresSQL
)

func (css CredentialDataMgrStore) String() string {
	return [...]string{"datastore", "postgressql"}[css]
}
