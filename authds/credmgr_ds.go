package authds

import (
	"fmt"
	"strconv"
	"time"

	aucm "github.com/lidstromberg/auth/authcommon"
	lbcf "github.com/lidstromberg/config"
	lblog "github.com/lidstromberg/log"

	"cloud.google.com/go/datastore"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

//DsCredentialMgr handles interactions with the datastore account store
type DsCredentialMgr struct {
	CmDsClient *datastore.Client
	Bc         lbcf.ConfigSetting
}

//NewDsCredentialMgr creates a new credential manager
func NewDsCredentialMgr(ctx context.Context, bc lbcf.ConfigSetting) (*DsCredentialMgr, error) {
	preflight(ctx, bc)

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "NewDsCredentialMgr", "info", "start")
	}

	datastoreClient, err := datastore.NewClient(ctx, bc.GetConfigValue(ctx, "EnvAuthGcpProject"), option.WithGRPCConnectionPool(EnvClientPool))

	if err != nil {
		return nil, err
	}

	cm1 := &DsCredentialMgr{
		CmDsClient: datastoreClient,
		Bc:         bc,
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "NewDsCredentialMgr", "info", "end")
	}

	return cm1, nil
}

//GetAccountCredential gets an account credential based on an email address
func (credentialMgr *DsCredentialMgr) GetAccountCredential(ctx context.Context, emailAddress string) (*aucm.UserAccountCredential, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountCredential", "info", "start")
	}

	//projection queries don't deserialise time.Time (Date And Time in datastore) as of 30.07.2018
	//so we have to take the entire entity and then extract the parts we want... yay...
	candidate, err := credentialMgr.GetLoginProfileByEmail(ctx, emailAddress)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountCredential", "info", emailAddress)
		lblog.LogEvent("DsCredentialMgr", "GetAccountCredential", "info", "end")
	}

	if candidate.UserAccountID == "" {
		return nil, aucm.ErrAccountNotLocated
	}

	ucred := &aucm.UserAccountCredential{}
	ucred.UserAccountID = candidate.UserAccountID
	ucred.PasswordHash = candidate.PasswordHash
	ucred.TwoFactorEnabled = candidate.TwoFactorEnabled
	ucred.TwoFactorHash = candidate.TwoFactorHash
	ucred.LockoutEnabled = candidate.LockoutEnabled
	ucred.AccessFailedCount = candidate.AccessFailedCount
	ucred.LockoutEnd = candidate.LockoutEnd

	return ucred, nil
}

//SavedFailedLogin increments the count of failed logins
func (credentialMgr *DsCredentialMgr) SavedFailedLogin(ctx context.Context, emailAddress string) error {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SavedFailedLogin", "info", "start")
	}

	//get the account
	var accountIsLocked bool

	candidate, err := credentialMgr.GetLoginProfileByEmail(ctx, emailAddress)

	if err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SavedFailedLogin", "info", fmt.Sprintf("%v", candidate))
	}

	//if the query returned a result...
	if candidate.UserAccountID != "" {
		//this should be on by default, but set it back on in case it has been previously deactivated
		candidate.LockoutEnabled = true

		//prep a lockout time (15 minutes from now)
		lockoutTime := time.Now().Add(15 * time.Minute)

		//if the failed attempt count has reach 3 then set the lockout time
		//otherwise increment the failed login count
		if candidate.AccessFailedCount > 2 {
			candidate.LockoutEnd = &lockoutTime
			accountIsLocked = true
		} else {
			candidate.AccessFailedCount++
		}

		//then save the account details back
		_, err := credentialMgr.SaveAccount(ctx, candidate)

		if err != nil {
			return err
		}

		if accountIsLocked {
			return aucm.ErrAccountIsLocked
		}
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SavedFailedLogin", "info", "end")
	}

	return nil
}

//ResetFailedLogin clears the count of failed logins
func (credentialMgr *DsCredentialMgr) ResetFailedLogin(ctx context.Context, emailAddress string) error {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "ResetFailedLogin", "info", "start")
	}

	//get the account
	q := datastore.NewQuery(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress).
		Limit(1)

	var candidate aucm.UserAccount

	it := credentialMgr.CmDsClient.Run(ctx, q)

	for {
		_, err := it.Next(&candidate)

		if err == iterator.Done {
			break
		}

		if err != nil {
			if err != datastore.ErrNoSuchEntity {
				return err
			}
		}
	}

	//if the query returned a result...
	if candidate.UserAccountID != "" {

		//this should be on by default, but set it back on in case it has been previously deactivated
		candidate.LockoutEnabled = true

		//prep a lockout time (zero time)
		lockoutTime := time.Time{}

		//reset the lockout time and the failed login count
		candidate.LockoutEnd = &lockoutTime
		candidate.AccessFailedCount = 0

		//then save the account details back
		_, err := credentialMgr.SaveAccount(ctx, &candidate)

		if err != nil {
			return err
		}
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "ResetFailedLogin", "info", "end")
	}

	return nil
}

//GetAccountCount returns a count of entities with a specified email address
func (credentialMgr *DsCredentialMgr) GetAccountCount(ctx context.Context, emailAddress string) (int, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountCount", "info", "start")
	}

	q := datastore.NewQuery(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress)

	n, err := credentialMgr.CmDsClient.Count(ctx, q)

	if err != nil {
		if err != datastore.ErrNoSuchEntity {
			return 0, err
		}
		return 0, nil
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountCount", "info", strconv.Itoa(n))
		lblog.LogEvent("DsCredentialMgr", "GetAccountCount", "info", "end")
	}

	return n, nil
}

//GetLoginProfile gets an account based on a userid
func (credentialMgr *DsCredentialMgr) GetLoginProfile(ctx context.Context, userID string) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfile", "info", "start")
	}

	id, err := strconv.ParseInt(userID, 10, 64)

	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"), id, nil)
	accountKey.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var candidate aucm.UserAccount

	if err := credentialMgr.CmDsClient.Get(ctx, accountKey, &candidate); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, aucm.ErrAccountNotLocated
		}
		return nil, err
	}

	if candidate.UserAccountID == "" {
		return nil, aucm.ErrAccountNotLocated
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfile", "info", "end")
	}

	return &candidate, nil
}

//GetLoginProfileByEmail gets an account based on an email address
func (credentialMgr *DsCredentialMgr) GetLoginProfileByEmail(ctx context.Context, emailAddress string) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfileByEmail", "info", "start")
	}

	//get the account
	q := datastore.NewQuery(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress).
		Limit(1)

	var candidate aucm.UserAccount

	it := credentialMgr.CmDsClient.Run(ctx, q)

	for {
		_, err := it.Next(&candidate)

		if err == iterator.Done {
			break
		}

		if err != nil {
			if err != datastore.ErrNoSuchEntity {
				return nil, err
			}
		}
	}

	if candidate.UserAccountID == "" {
		return nil, aucm.ErrAccountNotLocated
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfileByEmail", "info", "end")
	}

	return &candidate, nil
}

//GetAccountApp returns an array of applications for a given account
func (credentialMgr *DsCredentialMgr) GetAccountApp(ctx context.Context, userID string) ([]*aucm.UserAccountApplication, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountApp", "info", "start")
	}

	uacc, err := credentialMgr.GetLoginProfile(ctx, userID)

	if err != nil {
		return nil, err
	}

	accapps := uacc.Scopes

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountApp", "info", "end")
	}
	return accapps, nil
}

//SaveAccount saves data back to datastore
func (credentialMgr *DsCredentialMgr) SaveAccount(ctx context.Context, userAccount *aucm.UserAccount) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccount", "info", "start")
	}

	//mark update time
	nowTime := time.Now()
	userAccount.LastTouched = &nowTime

	id, err := strconv.ParseInt(userAccount.UserAccountID, 10, 64)

	if err != nil {
		return "", err
	}

	accountKey := datastore.IDKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"), id, nil)
	accountKey.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	tx, err := credentialMgr.CmDsClient.NewTransaction(ctx)

	if err != nil {
		return "", err
	}

	if _, err := tx.Put(accountKey, userAccount); err != nil {
		tx.Rollback()
		return "", err
	}

	if _, err = tx.Commit(); err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccount", "info", "end")
	}
	return userAccount.UserAccountID, nil
}

//StartAccountConfirmation generates a token for the user confirmation email
func (credentialMgr *DsCredentialMgr) StartAccountConfirmation(ctx context.Context, userID, emailAddress, userAccountConfirmationType, url, urlrd, sender, sendername string) (*aucm.UserEmailConfirm, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "StartAccountConfirmation", "info", "start")
	}

	var (
		returnConf aucm.UserEmailConfirm
		accToken   aucm.UserAccountConfirmation
	)
	currentTime := time.Now()
	expiryTime := currentTime.Add(time.Hour * 24)

	acctokenKey, err := credentialMgr.newKey(ctx, credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"))

	if err != nil {
		return nil, err
	}

	accToken.ConfirmToken = strconv.FormatInt(acctokenKey.ID, 10)
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

	tx, err := credentialMgr.CmDsClient.NewTransaction(ctx)

	if err != nil {
		return nil, err
	}

	if _, err := tx.Put(acctokenKey, &accToken); err != nil {
		tx.Rollback()
		return nil, err
	}

	if _, err = tx.Commit(); err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "StartAccountConfirmation", "info", "end")
	}
	return &returnConf, nil
}

//GetAccountConfirmation returns the account confirmation object associated with the userAccountToken
func (credentialMgr *DsCredentialMgr) GetAccountConfirmation(ctx context.Context, userAccountToken string) (*aucm.UserAccountConfirmation, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountConfirmation", "info", "start")
	}

	id, err := strconv.ParseInt(userAccountToken, 10, 64)

	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"), id, nil)
	accountKey.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var accToken aucm.UserAccountConfirmation

	err = credentialMgr.CmDsClient.Get(ctx, accountKey, &accToken)

	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, aucm.ErrConfirmTokenInvalid
		}
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountConfirmation", "info", "end")
	}
	return &accToken, nil
}

//SaveAccountConfirmation indicates that the user account has returned the confirmtoken after account registration
func (credentialMgr *DsCredentialMgr) SaveAccountConfirmation(ctx context.Context, userAccountConf *aucm.UserAccountConfirmation) (*aucm.UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccountConfirmation", "info", "start")
	}

	res := &aucm.UserAccountConfirmationResult{Result: false}

	id, err := strconv.ParseInt(userAccountConf.ConfirmToken, 10, 64)

	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"), id, nil)
	accountKey.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var tx *datastore.Transaction

	tx, err = credentialMgr.CmDsClient.NewTransaction(ctx)

	if err != nil {
		return res, err
	}

	if _, err := tx.Put(accountKey, userAccountConf); err != nil {
		tx.Rollback()
		return res, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccountConfirmation", "info", "completed put")
	}

	if _, err = tx.Commit(); err != nil {
		return res, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccountConfirmation", "info", "completed commit")
	}

	res.Result = true
	res.RedirectLink = userAccountConf.RedirectLink
	res.UserAccountConfirmationType = userAccountConf.UserAccountConfirmationType

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccountConfirmation", "info", "end")
	}
	return res, nil
}

//GetSystemDefault returns a system default value
func (credentialMgr *DsCredentialMgr) GetSystemDefault(ctx context.Context, systemKey string) (*aucm.SystemDefault, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetSystemDefault", "info", "start")
	}

	setky := datastore.NameKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsSysDefaultKind"), systemKey, nil)
	setky.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var setting aucm.SystemDefault

	err := credentialMgr.CmDsClient.Get(ctx, setky, &setting)

	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, aucm.ErrSysDefNotExist
		}
		return nil, err
	}

	if setting.ItemKey == "" {
		return nil, aucm.ErrSysDefNotExist
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetSystemDefault", "info", "end")
	}
	return &setting, nil
}

//SaveSystemDefault sets a system default value
func (credentialMgr *DsCredentialMgr) SaveSystemDefault(ctx context.Context, systemKey, systemVal string) error {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveSystemDefault", "info", "start")
	}

	sysdef := &aucm.SystemDefault{ItemKey: systemKey, ItemValue: systemVal}

	setky := datastore.NameKey(credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsSysDefaultKind"), systemKey, nil)
	setky.Namespace = credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	tx, err := credentialMgr.CmDsClient.NewTransaction(ctx)

	if err != nil {
		return err
	}

	if _, err := tx.Put(setky, sysdef); err != nil {
		tx.Rollback()
		return err
	}

	if _, err = tx.Commit(); err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveSystemDefault", "info", "end")
	}
	return nil
}

//newKey is datastore specific and returns a key using datastore.AllocateIDs
func (credentialMgr *DsCredentialMgr) newKey(ctx context.Context, dsNS, dsKind string) (*datastore.Key, error) {
	var keys []*datastore.Key

	//create an incomplete key of the type and namespace
	newKey := datastore.IncompleteKey(dsKind, nil)
	newKey.Namespace = dsNS

	//append it to the slice
	keys = append(keys, newKey)

	//allocate the ID from datastore
	keys, err := credentialMgr.CmDsClient.AllocateIDs(ctx, keys)

	if err != nil {
		return nil, err
	}

	//return only the first key
	return keys[0], nil
}

//NewAccountID returns a new id key for the account entity
func (credentialMgr *DsCredentialMgr) NewAccountID(ctx context.Context) (string, error) {
	key, err := credentialMgr.newKey(ctx, credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"))

	if err != nil {
		return "", err
	}

	return strconv.FormatInt(key.ID, 10), nil
}

//NewConfirmID returns a new id key for the confirmation entity
func (credentialMgr *DsCredentialMgr) NewConfirmID(ctx context.Context) (string, error) {
	key, err := credentialMgr.newKey(ctx, credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.Bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"))

	if err != nil {
		return "", err
	}

	return strconv.FormatInt(key.ID, 10), nil
}