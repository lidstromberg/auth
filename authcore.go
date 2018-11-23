package auth

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"time"

	aucm "github.com/lidstromberg/auth/authcommon"
	authds "github.com/lidstromberg/auth/authds"
	authpg "github.com/lidstromberg/auth/authpg"
	otp "github.com/lidstromberg/auth/otp"
	utils "github.com/lidstromberg/auth/utils"
	lbcf "github.com/lidstromberg/config"

	kp "github.com/lidstromberg/keypair"
	lblog "github.com/lidstromberg/log"
	sess "github.com/lidstromberg/session"

	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/net/context"
)

//AuthCore defines the full set of operations performed by the authentication service
type AuthCore interface {
	CreateAccountFromCandidate(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) (*aucm.UserAccount, error)
	AccountExists(ctx context.Context, emailAddress string) (bool, error)
	Register(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) (map[string]interface{}, error)
	LoginCheck(ctx context.Context, emailAddress string) *aucm.UserAccountLoginCheck
	Login(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) (map[string]interface{}, error)
	GetLoginProfile(ctx context.Context, userID string, withSecure bool) (*aucm.UserAccount, error)
	ToggleTwoFactor(ctx context.Context, domain, userID string, period int32, toggle, qr bool) *aucm.UserAccountOtpCheck
	SaveAccount(ctx context.Context, userAccount *aucm.UserAccount) (string, error)
	SavePassword(ctx context.Context, userID, newpwd string) (bool, error)
	RequestReset(ctx context.Context, emailAddress, appName string, liveCall bool) (string, error)
	FinishReset(ctx context.Context, userAccountToken, newpwd string) (*aucm.UserAccountConfirmationResult, error)
	StartAccountConfirmation(ctx context.Context, userID, email, appName string, liveCall bool) (string, error)
	FinishAccountConfirmation(ctx context.Context, userAccountToken string) (*aucm.UserAccountConfirmationResult, error)
	HasAccess(ctx context.Context, emailAddress, appName string) (bool, error)
	GetAccountRoleToken(ctx context.Context, userID string) (string, error)
	GetAccountRole(ctx context.Context, userID string) ([]*aucm.UserAccountApplication, error)
	VerifyCredential(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) *aucm.UserAccountPasswordCheck
	SaveEmailConfirmation(ctx context.Context, userAccountConf *aucm.UserAccountConfirmation) (*aucm.UserAccountConfirmationResult, error)
	SendMail(ctx context.Context, emailConfirm *aucm.UserEmailConfirm, appName string, liveCall bool) (bool, error)
}

//Core manages the issue log app operations
type Core struct {
	Dm aucm.CredentialDataMgr
	Mc *sendgrid.Client
	Kp *kp.KeyPair
	Bc lbcf.ConfigSetting
}

//NewCoreCredentialMgr creates a new credential base manager
func NewCoreCredentialMgr(ctx context.Context, bc lbcf.ConfigSetting, kpr *kp.KeyPair, mc *sendgrid.Client) (AuthCore, error) {

	preflight(ctx, bc)

	if EnvDebugOn {
		lblog.LogEvent("Core", "NewCoreCredentialMgr", "info", "start")
	}

	dm, err := newDataMgr(ctx, bc)

	if err != nil {
		return nil, err
	}

	ap1 := &Core{
		Dm: dm,
		Mc: mc,
		Kp: kpr,
		Bc: bc,
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "NewCoreCredentialMgr", "info", "end")
	}

	return ap1, nil
}

func newDataMgr(ctx context.Context, bc lbcf.ConfigSetting) (aucm.CredentialDataMgr, error) {
	var dm aucm.CredentialDataMgr

	switch bc.GetConfigValue(ctx, "EnvAuthDsType") {
	case "postgres":
		{
			cm1, err := authpg.NewPgCredentialMgr(ctx, bc)

			if err != nil {
				return nil, err
			}

			dm = cm1
		}
	case "datastore":
		{
			cm1, err := authds.NewDsCredentialMgr(ctx, bc)

			if err != nil {
				return nil, err
			}

			dm = cm1
		}
	default:
		{
			cm1, err := authpg.NewPgCredentialMgr(ctx, bc)

			if err != nil {
				return nil, err
			}

			dm = cm1
		}
	}

	if dm == nil {
		return nil, aucm.ErrCredentialDataMgrInvalid
	}

	return dm, nil
}

//CreateAccountFromCandidate converts a candidate to a useraccount with hashed password
func (cr *Core) CreateAccountFromCandidate(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "CreateAccountFromCandidate", "info", "start")
	}

	var (
		userAccount *aucm.UserAccount
		userApps    []*aucm.UserAccountApplication
	)

	currentTime := time.Now()
	zeroTime := time.Time{}
	accID, err := cr.Dm.NewAccountID(ctx)

	if err != nil {
		return nil, err
	}

	if pwdHash, err := utils.GetStringHash(userAccountCandidate.Password); err == nil {
		userAccount = &aucm.UserAccount{
			UserAccountID:        accID,
			Email:                userAccountCandidate.Email,
			PasswordHash:         pwdHash,
			EmailConfirmed:       false,
			LockoutEnabled:       true,
			AccessFailedCount:    0,
			LockoutEnd:           &currentTime,
			PhoneNumber:          "",
			PhoneNumberConfirmed: false,
			TwoFactorEnabled:     false,
			IsActive:             true,
			IsLockedForEdit:      false,
			Scopes:               userApps,
			CreatedDate:          &currentTime,
			RetiredDate:          &zeroTime,
			LastTouched:          &currentTime,
		}
	} else {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "CreateAccountFromCandidate", "info", "end")
	}

	return userAccount, nil
}

//AccountExists checks if an account is registered already
func (cr *Core) AccountExists(ctx context.Context, emailAddress string) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "AccountExists", "info", "start")
	}

	count, err := cr.Dm.GetAccountCount(ctx, emailAddress)

	if err != nil {
		return false, err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "AccountExists", "info", "end")
	}

	if count > 0 {
		return true, nil
	}

	return false, nil
}

//Register registers an account for the current application
func (cr *Core) Register(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) (map[string]interface{}, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "Register", "info", "start")
	}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		return nil, aucm.ErrEmailInvalid
	}

	//check that the account does not already exist
	accExist, err := cr.AccountExists(ctx, userAccountCandidate.Email)

	if err != nil {
		return nil, err
	}

	if accExist {
		return nil, aucm.ErrAccountIsRegistered
	}

	//then convert the candidate to a full account
	useracc, err := cr.CreateAccountFromCandidate(ctx, userAccountCandidate)

	if err != nil {
		return nil, err
	}

	//then automap the account to the current application
	currentTime := time.Now()
	zeroTime := time.Time{}

	uaccApp := &aucm.UserAccountApplication{}
	uaccApp.ApplicationName = appName
	uaccApp.IsActive = true
	uaccApp.CreatedDate = &currentTime
	uaccApp.RetiredDate = &zeroTime

	useracc.Scopes = append(useracc.Scopes, uaccApp)

	//save the account (returns true or error, so checking the error is enough)
	_, err = cr.Dm.SaveAccount(ctx, useracc)

	if err != nil {
		return nil, err
	}

	//get the authorisations token
	roletoken, err := cr.GetAccountRoleToken(ctx, useracc.UserAccountID)

	if err != nil {
		return nil, err
	}

	//create the base session header
	shdr := sess.MakeSessionMap(useracc.UserAccountID, useracc.Email, roletoken)

	if EnvDebugOn {
		// lblog.LogEvent("Core", "Register", "info", shdr.SessionID)
		// lblog.LogEvent("Core", "Register", "info", shdr.UserAccountID)
		// lblog.LogEvent("Core", "Register", "info", shdr.RoleTokenID)
		// lblog.LogEvent("Core", "Register", "info", shdr.Email)
		lblog.LogEvent("Core", "Register", "info", "end")
	}

	return shdr, nil
}

//LoginCheck checks for an account login options
func (cr *Core) LoginCheck(ctx context.Context, emailAddress string) *aucm.UserAccountLoginCheck {
	if EnvDebugOn {
		lblog.LogEvent("Core", "AccountExists", "info", "start")
	}

	chkr := &aucm.CheckResult{}
	cmpreslt := &aucm.UserAccountLoginCheck{Check: chkr}

	//reject if this is an invalid email
	if !utils.EmailIsValid(emailAddress) {
		cmpreslt.Check.CheckResult = false
		cmpreslt.Check.Error = aucm.ErrEmailInvalid

		return cmpreslt
	}

	//see if the account exists..
	chk, err := cr.AccountExists(ctx, emailAddress)

	if err != nil {
		cmpreslt.Check.CheckResult = false
		cmpreslt.Check.Error = err

		return cmpreslt
	}

	//if the account doesn't exist then record this
	if !chk {
		cmpreslt.Check.CheckResult = false
		cmpreslt.Check.Error = aucm.ErrAccountNotExist

		return cmpreslt
	}

	//get the profile
	uacc, err := cr.Dm.GetLoginProfileByEmail(ctx, emailAddress)

	if err != nil {
		cmpreslt.Check.CheckResult = false
		cmpreslt.Check.Error = err

		return cmpreslt
	}

	//if the account has 2FA enabled then record this
	if uacc.TwoFactorEnabled {
		cmpreslt.IsTwoFactor = true
	} else {
		cmpreslt.IsTwoFactor = false
	}

	//prep a current time
	currentTime := time.Now()

	//if the account is locked then record this
	if uacc.LockoutEnd.After(currentTime) {
		cmpreslt.IsLocked = true
	} else {
		cmpreslt.IsLocked = false
	}

	//set the remaining values
	cmpreslt.Check.CheckResult = true
	cmpreslt.Check.CheckMessage = "success"
	cmpreslt.Check.Error = nil

	return cmpreslt
}

//Login logs in an existing user
func (cr *Core) Login(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) (map[string]interface{}, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "Login", "info", "start")
	}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		return nil, aucm.ErrEmailInvalid
	}

	//check the account exists
	accExist, err := cr.AccountExists(ctx, userAccountCandidate.Email)

	if err != nil {
		return nil, err
	}

	if !accExist {
		return nil, aucm.ErrAccountNotExist
	}

	//check the user has access to this app (will always return error if access is denied
	//so we ignore the boolean and check for the error
	if _, err := cr.HasAccess(ctx, userAccountCandidate.Email, appName); err != nil {
		return nil, err
	}

	//then check the credentials
	pwdchk := cr.VerifyCredential(ctx, userAccountCandidate)

	if !pwdchk.Check.CheckResult || pwdchk.Check.Error != nil {
		return nil, pwdchk.Check.Error
	}

	//and get the authorisations token
	roletoken, err := cr.GetAccountRoleToken(ctx, pwdchk.UserAccountID)

	if err != nil {
		return nil, err
	}

	//create the base session header
	shdr := sess.MakeSessionMap(pwdchk.UserAccountID, userAccountCandidate.Email, roletoken)

	if EnvDebugOn {
		lblog.LogEvent("Core", "Login", "info", "end")
	}
	return shdr, nil
}

//GetLoginProfile returns the user account profile
func (cr *Core) GetLoginProfile(ctx context.Context, userID string, withSecure bool) (*aucm.UserAccount, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "GetLoginProfile", "info", "start")
	}

	useracc, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		return nil, err
	}

	if withSecure {
		useracc.PasswordHash = ""
		useracc.TwoFactorHash = ""
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "GetLoginProfile", "info", "end")
	}
	return useracc, nil
}

//ToggleTwoFactor switches two factor authentication on/off
func (cr *Core) ToggleTwoFactor(ctx context.Context, domain, userID string, period int32, toggle, qr bool) *aucm.UserAccountOtpCheck {
	if EnvDebugOn {
		lblog.LogEvent("Core", "ToggleTwoFactor", "info", "start")
	}

	chkr := &aucm.CheckResult{}
	confres := &aucm.UserAccountOtpCheck{Check: chkr}

	//get the profile
	uacc, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		confres.Check.CheckResult = false
		confres.Check.Error = err
		confres.Check.CheckMessage = err.Error()

		return confres
	}

	//if 2FA is on..
	if toggle {
		//exit if it is already on..
		if uacc.TwoFactorEnabled {
			confres.Check.CheckResult = true
			confres.Check.Error = nil
			confres.Check.CheckMessage = "preenabled"

			return confres
		}

		//otherwise generate a new otp key result
		rslt, err := otp.GenerateOtp(domain, uacc.Email, uint(period))

		if err != nil {
			confres.Check.CheckResult = false
			confres.Check.Error = err
			confres.Check.CheckMessage = err.Error()

			return confres
		}

		//turn the secret into an encrypted base64 string
		twofachash, err := cr.Kp.EncryptBytes(ctx, []byte(rslt.Secret))

		if err != nil {
			confres.Check.CheckResult = false
			confres.Check.Error = err
			confres.Check.CheckMessage = err.Error()

			return confres
		}

		//base64 the QR bytes
		qrc := base64.StdEncoding.EncodeToString(rslt.Img)

		//update the user account record
		uacc.TwoFactorEnabled = true
		uacc.TwoFactorHash = twofachash

		if qr {
			confres.Qr = qrc
		}
	} else {
		//or switch off 2FA and clear the secret and qr
		uacc.TwoFactorEnabled = false
		uacc.TwoFactorHash = ""
	}

	//save the account
	_, err = cr.SaveAccount(ctx, uacc)

	if err != nil {
		confres.Check.CheckResult = false
		confres.Check.Error = err
		confres.Check.CheckMessage = err.Error()

		return confres
	}

	confres.Check.CheckResult = true
	confres.Check.Error = nil
	confres.Check.CheckMessage = "success"

	return confres
}

//SaveAccount saves a user account back to the store
func (cr *Core) SaveAccount(ctx context.Context, userAccount *aucm.UserAccount) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveAccount", "info", "start")
	}

	//if this is a secured version of the user account, then restore the secured elements
	if userAccount.PasswordHash == "" {
		acc, err := cr.GetLoginProfile(ctx, userAccount.UserAccountID, false)
		if err != nil {
			return "", err
		}

		userAccount.PasswordHash = acc.PasswordHash

		if userAccount.TwoFactorHash == "" {
			userAccount.TwoFactorHash = acc.TwoFactorHash
		}
	}

	result, err := cr.Dm.SaveAccount(ctx, userAccount)

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveAccount", "info", "end")
	}
	return result, nil
}

//SavePassword saves a password change
func (cr *Core) SavePassword(ctx context.Context, userID, newpwd string) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SavePassword", "info", "start")
	}

	//hash the new password
	pwdHash, err := utils.GetStringHash(newpwd)

	if err != nil {
		return false, err
	}

	//get the account
	userAccount, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		return false, err
	}

	//set the new password
	userAccount.PasswordHash = pwdHash

	//save the account
	uaccid, err := cr.Dm.SaveAccount(ctx, userAccount)

	if err != nil {
		return false, err
	}

	if uaccid == "" {
		return false, aucm.ErrFailedToSave
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "SavePassword", "info", "end")
	}
	return true, nil
}

//RequestReset despatches password reset email
func (cr *Core) RequestReset(ctx context.Context, emailAddress, appName string, liveCall bool) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "CredentialReset", "info", "start")
	}

	//reject if this is an invalid email
	if !utils.EmailIsValid(emailAddress) {
		return "", aucm.ErrEmailInvalid
	}

	userid, err := cr.Dm.GetLoginProfileByEmail(ctx, emailAddress)

	if err != nil {
		return "", err
	}

	if userid.UserAccountID == "" {
		return "", aucm.ErrAccountNotExist
	}

	emconf, err := cr.Dm.StartAccountConfirmation(ctx, userid.UserAccountID, emailAddress, aucm.CredentialReset.String(), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthAccountConfirmationRedirectURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderAccount"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderName"))

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "CredentialReset", "info", emconf.ConfirmToken)
		lblog.LogEvent("Core", "CredentialReset", "info", emconf.ConfirmURL)
		lblog.LogEvent("Core", "CredentialReset", "info", emconf.Email)
		lblog.LogEvent("Core", "CredentialReset", "info", emconf.EmailSender)
		lblog.LogEvent("Core", "CredentialReset", "info", emconf.UserAccountConfirmationType)
	}

	if emconf == nil {
		return "", aucm.ErrAccountRegNotCompleted
	}

	result, err := cr.SendMail(ctx, emconf, appName, liveCall)

	if err != nil {
		return "", err
	}

	if !result {
		return "", aucm.ErrMailConfirmNotCompleted
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "CredentialReset", "info", "end")
	}
	return emconf.ConfirmToken, nil
}

//FinishReset completes a two-part account reset process
func (cr *Core) FinishReset(ctx context.Context, userAccountToken, newpwd string) (*aucm.UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "FinishReset", "info", "start")
	}

	accconf, err := cr.Dm.GetAccountConfirmation(ctx, userAccountToken)

	if err != nil {
		return nil, err
	}

	if accconf.TokenUsed || accconf.ExpiryDate.Before(time.Now()) {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	currentTime := time.Now()

	accconf.TokenUsed = true
	accconf.ActivatedDate = &currentTime

	//save/verify the token
	confres, err := cr.Dm.SaveAccountConfirmation(ctx, accconf)

	if err != nil {
		return nil, err
	}

	if !confres.Result {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	//mark the email confirmed flag on the account
	_, err = cr.SaveEmailConfirmation(ctx, accconf)

	if err != nil {
		return nil, err
	}

	//save the new password against the account
	_, err = cr.SavePassword(ctx, accconf.UserAccountID, newpwd)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "FinishAccountConfirmation", "info", "end")
	}
	//return the result
	return confres, nil
}

//StartAccountConfirmation begins the mail confirmation cycle for a new account
func (cr *Core) StartAccountConfirmation(ctx context.Context, userID, email, appName string, liveCall bool) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "StartAccountConfirmation", "info", "start")
	}

	//reject if this is an invalid email
	if !utils.EmailIsValid(email) {
		return "", aucm.ErrEmailInvalid
	}

	emconf, err := cr.Dm.StartAccountConfirmation(ctx, userID, email, "registration", cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthAccountConfirmationRedirectURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderAccount"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderName"))

	if err != nil {
		return "", err
	}

	if emconf == nil {
		return "", aucm.ErrAccountRegNotCompleted
	}

	if EnvDebugOn {
		// lblog.LogEvent("Core", "StartAccountConfirmation", "info", emconf.ConfirmToken)
		// lblog.LogEvent("Core", "StartAccountConfirmation", "info", emconf.ConfirmURL)
		// lblog.LogEvent("Core", "StartAccountConfirmation", "info", emconf.Email)
		// lblog.LogEvent("Core", "StartAccountConfirmation", "info", emconf.EmailSender)
		lblog.LogEvent("Core", "StartAccountConfirmation", "info", emconf.UserAccountConfirmationType)
	}

	result, err := cr.SendMail(ctx, emconf, appName, liveCall)

	if err != nil {
		return "", err
	}

	if !result {
		return "", aucm.ErrMailConfirmNotCompleted
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "StartAccountConfirmation", "info", "end")
	}
	return emconf.ConfirmToken, nil
}

//FinishAccountConfirmation completes a two-part confirmation process (such as registration or credential reset)
func (cr *Core) FinishAccountConfirmation(ctx context.Context, userAccountToken string) (*aucm.UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "FinishAccountConfirmation", "info", "start")
	}

	accconf, err := cr.Dm.GetAccountConfirmation(ctx, userAccountToken)

	if err != nil {
		return nil, err
	}

	if accconf.TokenUsed || accconf.ExpiryDate.Before(time.Now()) {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	currentTime := time.Now()

	accconf.TokenUsed = true
	accconf.ActivatedDate = &currentTime

	//save/verify the token
	confres, err := cr.Dm.SaveAccountConfirmation(ctx, accconf)

	if err != nil {
		return nil, err
	}

	if !confres.Result {
		return nil, aucm.ErrConfirmTokenInvalid
	}

	//mark the email confirmed flag on the account
	_, err = cr.SaveEmailConfirmation(ctx, accconf)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "FinishAccountConfirmation", "info", "end")
	}
	//return the result
	return confres, nil
}

//HasAccess checks if the candidate has app access
func (cr *Core) HasAccess(ctx context.Context, emailAddress, appName string) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "HasAccess", "info", "start")
	}

	//reject if this is an invalid email
	if !utils.EmailIsValid(emailAddress) {
		return false, aucm.ErrEmailInvalid
	}

	//get the profile
	uacc1, err := cr.Dm.GetLoginProfileByEmail(ctx, emailAddress)

	if err != nil {
		return false, err
	}

	//if the account hasn't been confirmed, or if it is locked out, then don't provide access
	if !uacc1.EmailConfirmed || uacc1.LockoutEnd.After(time.Now()) {
		return false, nil
	}

	//check the user has access to this app
	for _, item := range uacc1.Scopes {
		if item.ApplicationName == appName && item.IsActive == true {
			return true, nil
		}
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "HasAccess", "info", "end")
	}

	return false, nil
}

//GetAccountRoleToken returns a delimited tokenstring of apps which the user account has access to
func (cr *Core) GetAccountRoleToken(ctx context.Context, userID string) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "GetAccountRoleToken", "info", "start")
	}

	//get the profile
	uacc1, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		return "", err
	}

	accapps := uacc1.Scopes

	var userAppRoleKey bytes.Buffer

	for _, item := range accapps {
		if item.IsActive {
			userAppRoleKey.WriteString(item.ApplicationName)
			userAppRoleKey.WriteString(cr.Bc.GetConfigValue(ctx, "EnvAuthAppRoleDelim"))
		}
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "GetAccountRoleToken", "info", "end")
	}

	return userAppRoleKey.String(), nil
}

//GetAccountRole returns an array of apps which the user account has access to
func (cr *Core) GetAccountRole(ctx context.Context, userID string) ([]*aucm.UserAccountApplication, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "GetAccountRole", "info", "start")
	}

	//get the profile
	uacc1, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		return nil, err
	}

	accapps := uacc1.Scopes

	if EnvDebugOn {
		lblog.LogEvent("Core", "GetAccountRole", "info", "end")
	}

	return accapps, nil
}

//VerifyCredential checks that an email/password combination is valid
func (cr *Core) VerifyCredential(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) *aucm.UserAccountPasswordCheck {
	if EnvDebugOn {
		lblog.LogEvent("Core", "VerifyCredential", "info", "start")
	}

	chkr := &aucm.CheckResult{}
	cmpreslt := &aucm.UserAccountPasswordCheck{Check: chkr}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		cmpreslt.Check.Error = aucm.ErrEmailInvalid

		return cmpreslt
	}

	//see if the account exists..
	ctd, err := cr.Dm.GetAccountCount(ctx, userAccountCandidate.Email)

	if err != nil {
		cmpreslt.Check.Error = err
		cmpreslt.Check.CheckResult = false

		return cmpreslt
	}

	//if the count is zero then return
	if ctd == 0 {
		cmpreslt.Check.Error = aucm.ErrAccountNotLocated
		cmpreslt.Check.CheckResult = false

		return cmpreslt
	}

	//get the credential element of the account
	candidate, err := cr.Dm.GetAccountCredential(ctx, userAccountCandidate.Email)

	if err != nil {
		cmpreslt.Check.Error = err
		cmpreslt.Check.CheckResult = false

		return cmpreslt
	}

	//deal with 2FA first because it expires in 30 seconds
	if candidate.TwoFactorEnabled {

		if EnvDebugOn {
			lblog.LogEvent("Core", "VerifyCredential", "2FAOTP", userAccountCandidate.Otp)
		}

		if userAccountCandidate.Otp == "" {
			cmpreslt.Check.CheckResult = false
			cmpreslt.Check.Error = aucm.ErrOtpNotExist

			return cmpreslt
		}

		//decrypt the secret
		secret, err := cr.Kp.DecryptString(ctx, candidate.TwoFactorHash)

		if err != nil {
			cmpreslt.Check.CheckResult = false
			cmpreslt.Check.Error = err

			return cmpreslt
		}

		//exit if the passcode was not valid
		if !otp.VerifyOtp(userAccountCandidate.Otp, secret) {
			cmpreslt.Check.CheckResult = false
			cmpreslt.Check.Error = otp.ErrPasscodeNotValid

			return cmpreslt
		}
	}

	//prep a current time
	currentTime := time.Now()

	//if the account is locked then return the error
	if candidate.LockoutEnd.After(currentTime) {
		cmpreslt.Check.Error = aucm.ErrAccountIsLocked
		cmpreslt.Check.CheckResult = false

		return cmpreslt
	}

	//now check the credentials match
	chk, err := utils.GetHashCompare(candidate.PasswordHash, userAccountCandidate.Password)

	//if there was an error..
	if err != nil {
		cmpreslt.Check.CheckResult = false
		cmpreslt.Check.Error = err

		//if the error is that the password was incorrect..
		if err == utils.ErrCredentialsNotCorrect {
			//save the failed login attempt
			lgerr := cr.Dm.SavedFailedLogin(ctx, userAccountCandidate.Email)

			if lgerr != nil {
				cmpreslt.Check.CheckResult = false
				cmpreslt.Check.Error = lgerr
			}
		}

		return cmpreslt
	}

	//we reach this point if the credential check was successful
	//if there were previous failed login attempts.. then reset the count.. because all is good now
	if candidate.AccessFailedCount > 0 {
		lgerr := cr.Dm.ResetFailedLogin(ctx, userAccountCandidate.Email)

		if lgerr != nil {
			cmpreslt.Check.CheckResult = false
			cmpreslt.Check.Error = lgerr

			return cmpreslt
		}
	}

	//and finally prep the results
	if chk {
		cmpreslt.Check.CheckResult = chk
		cmpreslt.UserAccountID = candidate.UserAccountID
		cmpreslt.Check.Error = nil
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "VerifyCredential", "info", "end")
	}

	return cmpreslt
}

//SaveEmailConfirmation sets the account record to indicate email confirmation
func (cr *Core) SaveEmailConfirmation(ctx context.Context, userAccountConf *aucm.UserAccountConfirmation) (*aucm.UserAccountConfirmationResult, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveEmailConfirmation", "info", "start")
	}

	res := &aucm.UserAccountConfirmationResult{Result: false}
	currentTime := time.Now()

	if userAccountConf.UserAccountConfirmationType == aucm.Registration.String() {
		uacc, err := cr.Dm.GetLoginProfile(ctx, userAccountConf.UserAccountID)

		if err != nil {
			return res, err
		}

		if uacc == nil {
			return res, aucm.ErrAccountNotLocated
		}

		if !uacc.EmailConfirmed {
			uacc.EmailConfirmed = true
			uacc.LastTouched = &currentTime

			uaccid, err := cr.Dm.SaveAccount(ctx, uacc)

			if err != nil {
				return res, err
			}

			if uaccid == "" {
				return res, aucm.ErrAccountCannotBeCreated
			}
		}
	}

	res.Result = true
	res.UserAccountConfirmationType = userAccountConf.UserAccountConfirmationType
	res.RedirectLink = userAccountConf.RedirectLink

	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveEmailConfirmation", "info", "end")
	}
	return res, nil
}

//SendMail calls the mail client to send an email
func (cr *Core) SendMail(ctx context.Context, emailConfirm *aucm.UserEmailConfirm, appName string, liveCall bool) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SendMail", "info", "start")
	}

	//reject if either sender or recipient is an invalid email
	if !utils.EmailIsValid(emailConfirm.EmailSender) || !utils.EmailIsValid(emailConfirm.Email) {
		if EnvDebugOn {
			lblog.LogEvent("Core", "SendMail", "info", emailConfirm.EmailSender)
			lblog.LogEvent("Core", "SendMail", "info", emailConfirm.Email)
		}
		return false, aucm.ErrEmailInvalid
	}

	var subject, plainTextContent, htmlContent string

	from := mail.NewEmail(emailConfirm.EmailSenderName, emailConfirm.EmailSender)
	to := mail.NewEmail(emailConfirm.Email, emailConfirm.Email)

	switch emailConfirm.UserAccountConfirmationType {
	case aucm.Registration.String():
		{
			subject = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegSubject"), appName)
			plainTextContent = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegPlainTxt"), emailConfirm.ConfirmURL, emailConfirm.ConfirmToken)
			htmlContent = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegHTML"), emailConfirm.ConfirmURL, emailConfirm.ConfirmToken)
		}
	case aucm.CredentialReset.String():
		{
			subject = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegSubject"), appName)
			plainTextContent = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegPlainTxt"), emailConfirm.ConfirmURL, emailConfirm.ConfirmToken)
			htmlContent = fmt.Sprintf(cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountRegHTML"), emailConfirm.ConfirmURL, emailConfirm.ConfirmToken)
		}
	default:
		return false, aucm.ErrMailConfirmNotCompleted
	}

	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)

	if liveCall {
		response, err := cr.Mc.Send(message)

		if err != nil {
			return false, err
		}

		if EnvDebugOn {
			lblog.LogEvent("Core", "SendMail", "info", strconv.Itoa(response.StatusCode))
		}
	}

	if EnvDebugOn {
		// lblog.LogEvent("Core", "SendMail", "message.From.Name", message.From.Name)
		// lblog.LogEvent("Core", "SendMail", "to.Name", to.Name)
		// lblog.LogEvent("Core", "SendMail", "info", message.Subject)
		// lblog.LogEvent("Core", "SendMail", "plainTextContent", plainTextContent)
		// lblog.LogEvent("Core", "SendMail", "htmlContent", htmlContent)
		lblog.LogEvent("Core", "SendMail", "info", "end")
	}

	return true, nil
}

//GetSystemDefault returns a system default setting
func (cr *Core) GetSystemDefault(ctx context.Context, systemKey string) (*aucm.SystemDefault, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "GetSystemDefault", "info", "start")
	}

	//get the setting
	sd, err := cr.Dm.GetSystemDefault(ctx, systemKey)

	if err != nil {
		return nil, err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "GetSystemDefault", "info", "end")
	}

	return sd, nil
}

//SetSystemDefault saves a system default setting
func (cr *Core) SetSystemDefault(ctx context.Context, systemKey, systemVal string) error {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SetSystemDefault", "info", "start")
	}

	//set the value
	err := cr.Dm.SaveSystemDefault(ctx, systemKey, systemVal)

	if err != nil {
		return err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "SetSystemDefault", "info", "end")
	}
	return nil
}
