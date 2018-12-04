package authpg

import (
	"database/sql"
	"fmt"
	"strings"

	"time"

	"encoding/json"

	aucm "github.com/lidstromberg/auth/authcommon"
	lbcf "github.com/lidstromberg/config"
	lblog "github.com/lidstromberg/log"
	utils "github.com/lidstromberg/utils"

	//github.com/lib/pq this is required as a blank import for database interactions
	//_ "github.com/lib/pq"
	//this is for utilising the GCP Cloud SQL proxy
	_ "github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/postgres"
	context "golang.org/x/net/context"
)

//PgCredentialMgr handles interactions with the database
type PgCredentialMgr struct {
	CmDsClient *sql.DB
	Bc         lbcf.ConfigSetting
}

//NewPgCredentialMgr creates a new credential manager
func NewPgCredentialMgr(ctx context.Context, bc lbcf.ConfigSetting) (*PgCredentialMgr, error) {
	preflight(ctx, bc)

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "NewPgCredentialMgr", "info", "start")
	}

	db, err := sql.Open(bc.GetConfigValue(ctx, "EnvAuthSQLDataSourceType"), bc.GetConfigValue(ctx, "EnvAuthSQLConnectionString"))

	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	cm1 := &PgCredentialMgr{
		CmDsClient: db,
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "NewPgCredentialMgr", "info", "end")
	}

	return cm1, nil
}

//GetAccountCredential gets an account credential based on an email address
func (credentialMgr *PgCredentialMgr) GetAccountCredential(ctx context.Context, emailAddress string) (*aucm.UserAccountCredential, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountCredential", "info", "start")
	}

	var (
		cred       aucm.UserAccountCredential
		jsonString sql.NullString
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_useraccountcredential from public.get_useraccountcredential($1)", emailAddress).Scan(&jsonString)

	if !jsonString.Valid {
		return nil, aucm.ErrCredentialsNotExist
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&cred)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountCredential", "info", "end")
	}

	return &cred, nil
}

//SavedFailedLogin increments the count of failed logins
func (credentialMgr *PgCredentialMgr) SavedFailedLogin(ctx context.Context, emailAddress string) error {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SavedFailedLogin", "info", "start")
	}

	var result bool

	err := credentialMgr.CmDsClient.QueryRow("select set_failedloginattempt from public.set_failedloginattempt($1)", emailAddress).Scan(&result)

	if err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SavedFailedLogin", "info", "end")
	}

	if result {
		return aucm.ErrAccountIsLocked
	}

	return nil
}

//ResetFailedLogin clears the count of failed logins
func (credentialMgr *PgCredentialMgr) ResetFailedLogin(ctx context.Context, emailAddress string) error {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "ResetFailedLogin", "info", "start")
	}

	var result bool

	err := credentialMgr.CmDsClient.QueryRow("select reset_failedloginattempt from public.reset_failedloginattempt($1)", emailAddress).Scan(&result)

	if err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "ResetFailedLogin", "info", "end")
	}

	return nil
}

//GetAccountCount returns a count of entities with a specified email address
func (credentialMgr *PgCredentialMgr) GetAccountCount(ctx context.Context, emailAddress string) (int, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountCount", "info", "start")
	}

	var counter int

	err := credentialMgr.CmDsClient.QueryRow("select count(*) get_useraccountbyemail from public.get_useraccountbyemail($1) where get_useraccountbyemail is not null", emailAddress).Scan(&counter)

	if err != nil {
		return 0, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountCount", "info", "end")
	}

	return counter, nil
}

//GetLoginProfile gets an account based on a userid
func (credentialMgr *PgCredentialMgr) GetLoginProfile(ctx context.Context, userID string) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetLoginProfile", "info", "start")
	}

	var (
		userAccount aucm.UserAccount
		jsonString  sql.NullString
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_useraccount from public.get_useraccount($1)", userID).Scan(&jsonString)

	if err != nil {
		return nil, err
	}

	if !jsonString.Valid {
		return nil, aucm.ErrAccountNotLocated
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&userAccount)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetLoginProfile", "info", "end")
	}

	return &userAccount, nil
}

//GetLoginProfileByEmail returns the userid of a specified email address
func (credentialMgr *PgCredentialMgr) GetLoginProfileByEmail(ctx context.Context, emailAddress string) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetLoginProfileByEmail", "info", "start")
	}

	var (
		userAccount aucm.UserAccount
		jsonString  sql.NullString
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_useraccountbyemail from public.get_useraccountbyemail($1)", emailAddress).Scan(&jsonString)

	if err != nil {
		return nil, err
	}

	if !jsonString.Valid {
		return nil, aucm.ErrAccountNotLocated
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&userAccount)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetLoginProfileByEmail", "info", "end")
	}

	return &userAccount, nil
}

//GetAccountApp returns an array of applications for a given account
func (credentialMgr *PgCredentialMgr) GetAccountApp(ctx context.Context, userID string) ([]*aucm.UserAccountApplication, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountApp", "info", "start")
	}

	var (
		jsonString sql.NullString
		accapps    []*aucm.UserAccountApplication
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_useraccountapplication from public.get_useraccountapplication($1)", userID).Scan(&jsonString)

	if err != nil {
		return nil, err
	}

	if !jsonString.Valid {
		return nil, aucm.ErrAccountAppMappingNotExist
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&accapps)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountApp", "info", "end")
	}
	return accapps, nil
}

//SaveAccount saves data back to datastore
func (credentialMgr *PgCredentialMgr) SaveAccount(ctx context.Context, userAccount *aucm.UserAccount) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveAccount", "info", "start")
	}

	var result sql.NullString

	uac1, err := json.Marshal(userAccount)

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveAccount", "payload", string(uac1))
	}

	err = credentialMgr.CmDsClient.QueryRow("select set_useraccount from public.set_useraccount($1)", string(uac1)).Scan(&result)

	if err != nil {
		return "", err
	}

	if !result.Valid {
		return "", nil
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveAccount", "info", "end")
	}
	return result.String, nil
}

//StartAccountConfirmation generates a token for the user confirmation email
func (credentialMgr *PgCredentialMgr) StartAccountConfirmation(ctx context.Context, userID, emailAddress, userAccountConfirmationType, url, urlrd, sender, sendername string) (*aucm.UserEmailConfirm, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "StartAccountConfirmation", "info", "start")
	}

	var (
		returnConf aucm.UserEmailConfirm
		accToken   aucm.UserAccountConfirmation
		result     bool
	)

	currentTime := time.Now()
	expiryTime := currentTime.Add(time.Hour * 24)

	accToken.ConfirmToken = utils.NewID()
	accToken.Email = emailAddress
	accToken.UserAccountID = userID
	accToken.TokenUsed = false
	accToken.UserAccountConfirmationType = userAccountConfirmationType
	accToken.RedirectLink = fmt.Sprintf(urlrd, accToken.ConfirmToken)
	accToken.CreatedDate = &currentTime
	accToken.ExpiryDate = &expiryTime

	returnConf.Email = emailAddress
	returnConf.ConfirmToken = accToken.ConfirmToken
	returnConf.ConfirmURL = fmt.Sprintf(url, accToken.ConfirmToken)
	returnConf.EmailSender = sender
	returnConf.EmailSenderName = sendername
	returnConf.UserAccountConfirmationType = userAccountConfirmationType

	jsonBytes, err := json.Marshal(accToken)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "StartAccountConfirmation", "payload", string(jsonBytes))
	}

	err = credentialMgr.CmDsClient.QueryRow("select public.start_useraccountconfirmation($1)", string(jsonBytes)).Scan(&result)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "StartAccountConfirmation", "info", "end")
	}
	return &returnConf, nil
}

//GetAccountConfirmation returns the account confirmation object associated with the userAccountToken
func (credentialMgr *PgCredentialMgr) GetAccountConfirmation(ctx context.Context, userAccountToken string) (*aucm.UserAccountConfirmation, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountConfirmation", "info", "start")
	}

	var (
		jsonString sql.NullString
		accToken   aucm.UserAccountConfirmation
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_useraccountconfirmation from public.get_useraccountconfirmation($1)", userAccountToken).Scan(&jsonString)

	if err != nil {
		return nil, err
	}

	if !jsonString.Valid {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&accToken)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetAccountConfirmation", "info", "end")
	}
	return &accToken, nil
}

//SaveAccountConfirmation indicates that the user account has returned the confirmtoken after account registration
func (credentialMgr *PgCredentialMgr) SaveAccountConfirmation(ctx context.Context, userAccountConf *aucm.UserAccountConfirmation) (*aucm.UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveAccountConfirmation", "info", "start")
	}

	var (
		res        aucm.UserAccountConfirmationResult
		jsonString sql.NullString
	)

	err := credentialMgr.CmDsClient.QueryRow("select finish_useraccountconfirmation from public.finish_useraccountconfirmation($1)", userAccountConf.ConfirmToken).Scan(&jsonString)

	if err != nil {
		return nil, err
	}

	if !jsonString.Valid {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	deco := json.NewDecoder(strings.NewReader(jsonString.String))

	err = deco.Decode(&res)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveAccountConfirmation", "info", "end")
	}
	return &res, nil
}

//GetSystemDefault returns a system default value
func (credentialMgr *PgCredentialMgr) GetSystemDefault(ctx context.Context, systemKey string) (*aucm.SystemDefault, error) {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetSystemDefault", "info", "start")
	}

	var (
		dbres   sql.NullString
		setting aucm.SystemDefault
	)

	err := credentialMgr.CmDsClient.QueryRow("select get_systemdefault from public.get_systemdefault($1)", systemKey).Scan(&dbres)

	if err != nil {
		return nil, err
	}

	//if there isn't a configured value then treat this as an empty string (there doesn't *need* to be a value)
	if !dbres.Valid {
		return nil, nil
	}

	deco := json.NewDecoder(strings.NewReader(dbres.String))

	err = deco.Decode(&setting)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "GetSystemDefault", "info", "end")
	}
	return &setting, nil
}

//SaveSystemDefault sets a system default value
func (credentialMgr *PgCredentialMgr) SaveSystemDefault(ctx context.Context, systemKey, systemVal string) error {
	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveSystemDefault", "info", "start")
	}

	var result bool

	err := credentialMgr.CmDsClient.QueryRow("select set_systemdefault from public.set_systemdefault($1,$2)", systemKey, systemVal).Scan(&result)

	if err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("PgCredentialMgr", "SaveSystemDefault", "info", "end")
	}
	return nil
}

//NewAccountID returns a new id key for the account entity
func (credentialMgr *PgCredentialMgr) NewAccountID(ctx context.Context) (string, error) {
	return utils.NewID(), nil
}

//NewConfirmID returns a new id key for the confirmation entity
func (credentialMgr *PgCredentialMgr) NewConfirmID(ctx context.Context) (string, error) {
	return utils.NewID(), nil
}
