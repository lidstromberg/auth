package auth

import (
	"fmt"
	"strconv"
	"time"

	lbcf "github.com/lidstromberg/config"
	lblog "github.com/lidstromberg/log"
	utils "github.com/lidstromberg/utils"

	"cloud.google.com/go/datastore"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

//DsCredentialMgr handles interactions with the datastore account store
type DsCredentialMgr struct {
	dsclient *datastore.Client
	bc       lbcf.ConfigSetting
}

//NewDsCredentialMgr creates a new credential manager
func NewDsCredentialMgr(ctx context.Context, bc lbcf.ConfigSetting) (*DsCredentialMgr, error) {
	preflightDs(ctx, bc)

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "NewDsCredentialMgr", "info", "start")
	}

	datastoreClient, err := datastore.NewClient(ctx, bc.GetConfigValue(ctx, "EnvAuthGcpProject"), option.WithGRPCConnectionPool(EnvClientPool))
	if err != nil {
		return nil, err
	}

	cm1 := &DsCredentialMgr{
		dsclient: datastoreClient,
		bc:       bc,
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "NewDsCredentialMgr", "info", "end")
	}

	return cm1, nil
}

//GetAccountCredential gets an account credential based on an email address
func (credentialMgr *DsCredentialMgr) GetAccountCredential(ctx context.Context, emailAddress string) (*UserAccountCredential, error) {
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
		return nil, ErrAccountNotLocated
	}

	ucred := &UserAccountCredential{}
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
			return ErrAccountIsLocked
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
	q := datastore.NewQuery(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress).
		Limit(1)

	var candidate UserAccount

	it := credentialMgr.dsclient.Run(ctx, q)

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

	q := datastore.NewQuery(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress)

	n, err := credentialMgr.dsclient.Count(ctx, q)

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
func (credentialMgr *DsCredentialMgr) GetLoginProfile(ctx context.Context, userID string) (*UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfile", "info", "start")
	}

	id, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"), id, nil)
	accountKey.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var candidate UserAccount

	if err := credentialMgr.dsclient.Get(ctx, accountKey, &candidate); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, ErrAccountNotLocated
		}
		return nil, err
	}

	if candidate.UserAccountID == "" {
		return nil, ErrAccountNotLocated
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfile", "info", "end")
	}

	return &candidate, nil
}

//GetLoginProfileByEmail gets an account based on an email address
func (credentialMgr *DsCredentialMgr) GetLoginProfileByEmail(ctx context.Context, emailAddress string) (*UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfileByEmail", "info", "start")
	}

	//get the account
	q := datastore.NewQuery(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind")).
		Namespace(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")).
		Filter("email =", emailAddress).
		Limit(1)

	var candidate UserAccount

	it := credentialMgr.dsclient.Run(ctx, q)

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
		return nil, ErrAccountNotLocated
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginProfileByEmail", "info", "end")
	}

	return &candidate, nil
}

//GetAccountApp returns an array of applications for a given account
func (credentialMgr *DsCredentialMgr) GetAccountApp(ctx context.Context, userID string) ([]*UserAccountApplication, error) {
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
func (credentialMgr *DsCredentialMgr) SaveAccount(ctx context.Context, userAccount *UserAccount) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccount", "info", "start")
	}

	//mark update time
	nowTime := time.Now()
	userAccount.LastTouched = &nowTime

	var key *datastore.Key

	if userAccount.UserAccountID == "" {
		key1, err := utils.NewDsKey(ctx, credentialMgr.dsclient, credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"))
		if err != nil {
			return "", err
		}

		key = key1
		userAccount.UserAccountID = strconv.FormatInt(key.ID, 10)
	} else {
		id, err := strconv.ParseInt(userAccount.UserAccountID, 10, 64)
		if err != nil {
			return "", err
		}

		key1 := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountKind"), id, nil)
		key1.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

		key = key1
	}

	tx, err := credentialMgr.dsclient.NewTransaction(ctx)
	if err != nil {
		return "", err
	}

	if _, err := tx.Put(key, userAccount); err != nil {
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
func (credentialMgr *DsCredentialMgr) StartAccountConfirmation(ctx context.Context, userID, emailAddress, userAccountConfirmationType, url, urlrd, sender, sendername string) (*UserEmailConfirm, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "StartAccountConfirmation", "info", "start")
	}

	var (
		returnConf UserEmailConfirm
		accToken   UserAccountConfirmation
	)
	currentTime := time.Now()
	expiryTime := currentTime.Add(time.Hour * 24)

	acctokenKey, err := utils.NewDsKey(ctx, credentialMgr.dsclient, credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"))
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

	tx, err := credentialMgr.dsclient.NewTransaction(ctx)

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
func (credentialMgr *DsCredentialMgr) GetAccountConfirmation(ctx context.Context, userAccountToken string) (*UserAccountConfirmation, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountConfirmation", "info", "start")
	}

	id, err := strconv.ParseInt(userAccountToken, 10, 64)
	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"), id, nil)
	accountKey.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var accToken UserAccountConfirmation

	err = credentialMgr.dsclient.Get(ctx, accountKey, &accToken)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, ErrConfirmTokenInvalid
		}
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetAccountConfirmation", "info", "end")
	}
	return &accToken, nil
}

//SaveAccountConfirmation indicates that the user account has returned the confirmtoken after account registration
func (credentialMgr *DsCredentialMgr) SaveAccountConfirmation(ctx context.Context, userAccountConf *UserAccountConfirmation) (*UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "SaveAccountConfirmation", "info", "start")
	}

	res := &UserAccountConfirmationResult{Result: false}

	id, err := strconv.ParseInt(userAccountConf.ConfirmToken, 10, 64)
	if err != nil {
		return nil, err
	}

	accountKey := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind"), id, nil)
	accountKey.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var tx *datastore.Transaction

	tx, err = credentialMgr.dsclient.NewTransaction(ctx)
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

//SetLoginCandidate writes a login candidate to datastore
func (credentialMgr *DsCredentialMgr) SetLoginCandidate(ctx context.Context, lc *LoginCandidate) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "setLoginCandidate", "info", "start")
	}

	var key *datastore.Key

	if lc.LoginID == "" {
		key1, err := utils.NewDsKey(ctx, credentialMgr.dsclient, credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace"), credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsLoginKind"))
		if err != nil {
			return "", err
		}

		key = key1
		lc.LoginID = strconv.FormatInt(key.ID, 10)
	} else {
		id, err := strconv.ParseInt(lc.LoginID, 10, 64)
		if err != nil {
			return "", err
		}

		key1 := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsLoginKind"), id, nil)
		key1.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

		key = key1
	}

	tx, err := credentialMgr.dsclient.NewTransaction(ctx)

	if err != nil {
		return "", err
	}

	if _, err := tx.Put(key, lc); err != nil {
		tx.Rollback()
		return "", err
	}

	if _, err = tx.Commit(); err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "setLoginCandidate", "info", "end")
	}

	return lc.LoginID, nil
}

//GetLoginCandidate returns a login candidate record
func (credentialMgr *DsCredentialMgr) GetLoginCandidate(ctx context.Context, loginID string) (*LoginCandidate, error) {
	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginCandidate", "info", "start")
	}

	id, err := strconv.ParseInt(loginID, 10, 64)
	if err != nil {
		return nil, err
	}

	key := datastore.IDKey(credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsLoginKind"), id, nil)
	key.Namespace = credentialMgr.bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace")

	var lc LoginCandidate

	err = credentialMgr.dsclient.Get(ctx, key, &lc)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, ErrLcNotExist
		}
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("DsCredentialMgr", "GetLoginCandidate", "info", "end")
	}
	return &lc, nil
}
