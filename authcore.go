package auth

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"time"

	aucm "github.com/lidstromberg/auth/authcommon"
	authds "github.com/lidstromberg/auth/authds"
	otp "github.com/lidstromberg/auth/otp"
	lbcf "github.com/lidstromberg/config"
	utils "github.com/lidstromberg/utils"

	kp "github.com/lidstromberg/keypair"
	lblog "github.com/lidstromberg/log"
	sess "github.com/lidstromberg/session"

	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/net/context"
)

//MailerAction defines actions which are called as part of an email based workflow
type MailerAction interface {
	StartAccountConfirmation(ctx context.Context, userID, email, appName string, liveCall bool) (string, error)
	FinishAccountConfirmation(ctx context.Context, userAccountToken string) (*aucm.UserAccountConfirmationResult, error)
	SaveEmailConfirmation(ctx context.Context, userAccountConf *aucm.UserAccountConfirmation) (*aucm.UserAccountConfirmationResult, error)
	SendMail(ctx context.Context, emailConfirm *aucm.UserEmailConfirm, appName string, liveCall bool) (bool, error)
}

//AuthenticatedAction defines actions which require a user to be previously authenticated
type AuthenticatedAction interface {
	GetLoginProfile(ctx context.Context, userID string, withSecure bool) (*aucm.UserAccount, error)
	ToggleTwoFactor(ctx context.Context, domain, userID string, period int32, toggle, qr bool) *aucm.ToggleOtpResult
	SaveAccount(ctx context.Context, userAccount *aucm.UserAccount) (string, error)
	SavePassword(ctx context.Context, userID, newpwd string) (bool, error)
	HasAccess(ctx context.Context, emailAddress, appName string) (bool, error)
	GetAccountRoleToken(ctx context.Context, userID string) (string, error)
	GetAccountRole(ctx context.Context, userID string) ([]*aucm.UserAccountApplication, error)
}

//IdentityAction defines actions which are performed in order to identify/authenticate a user
type IdentityAction interface {
	Register(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) *aucm.RegisterCheckResult
	Login(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) *aucm.LoginCheckResult
	RequestReset(ctx context.Context, emailAddress, appName string) (string, error)
	FinishReset(ctx context.Context, userAccountToken, newpwd string) (*aucm.UserAccountConfirmationResult, error)
	AccountExists(ctx context.Context, emailAddress string) (bool, error)
	VerifyCredential(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) *aucm.PasswordCheckResult
}

//AuthCore defines the full set of operations performed by the authentication service
type AuthCore interface {
	CreateAccountFromCandidate(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) (*aucm.UserAccount, error)
	MailerAction
	AuthenticatedAction
	IdentityAction
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

	dm, err := authds.NewDsCredentialMgr(ctx, bc)
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
func (cr *Core) Register(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) *aucm.RegisterCheckResult {
	if EnvDebugOn {
		lblog.LogEvent("Core", "Register", "info", "start")
	}

	rcr := &aucm.RegisterCheckResult{Check: &aucm.CheckResult{}}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		rcr.Check.Error = aucm.ErrEmailInvalid
		rcr.Check.CheckResult = false

		return rcr
	}

	//check that the account does not already exist
	accExist, err := cr.AccountExists(ctx, userAccountCandidate.Email)
	if err != nil {
		rcr.Check.Error = err
		rcr.Check.CheckResult = false

		return rcr
	}

	if accExist {
		rcr.Check.Error = aucm.ErrAccountIsRegistered
		rcr.Check.CheckResult = false

		return rcr
	}

	//then convert the candidate to a full account
	useracc, err := cr.CreateAccountFromCandidate(ctx, userAccountCandidate)
	if err != nil {
		rcr.Check.Error = err
		rcr.Check.CheckResult = false

		return rcr
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

	//save the account
	userid, err := cr.Dm.SaveAccount(ctx, useracc)
	if err != nil {
		rcr.Check.Error = err
		rcr.Check.CheckResult = false

		return rcr
	}

	//start the mail confirmation
	emconf, err := cr.Dm.StartAccountConfirmation(ctx, userid, userAccountCandidate.Email, aucm.Registration.String(), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationRdURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderAccount"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderName"))
	if err != nil {
		rcr.Check.Error = err
		rcr.Check.CheckResult = false

		return rcr
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "Register", "info", emconf.ConfirmToken)
		lblog.LogEvent("Core", "Register", "info", emconf.ConfirmURL)
		lblog.LogEvent("Core", "Register", "info", emconf.Email)
		lblog.LogEvent("Core", "Register", "info", emconf.EmailSender)
		lblog.LogEvent("Core", "Register", "info", emconf.UserAccountConfirmationType)
	}

	if emconf == nil {
		rcr.Check.Error = aucm.ErrAccountRegNotCompleted
		rcr.Check.CheckResult = false

		return rcr
	}

	result, err := cr.SendMail(ctx, emconf, appName, true)
	if err != nil {
		rcr.Check.Error = err
		rcr.Check.CheckResult = false

		return rcr
	}

	if !result {
		rcr.Check.Error = aucm.ErrMailConfirmNotCompleted
		rcr.Check.CheckResult = false

		return rcr
	}

	//set the remaining values
	rcr.Check.CheckResult = true
	rcr.Check.CheckMessage = "success"
	rcr.Check.Error = nil
	rcr.ConfirmToken = emconf.ConfirmToken

	if EnvDebugOn {
		lblog.LogEvent("Core", "Register", "info", "end")
	}

	return rcr
}

//Login logs in an existing user
func (cr *Core) Login(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate, appName string) *aucm.LoginCheckResult {
	if EnvDebugOn {
		lblog.LogEvent("Core", "Login", "info", "start")
	}

	//setup the return value
	hdr := make(map[string]interface{})
	lcr := &aucm.LoginCheckResult{Header: hdr}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		lcr.Check.Error = aucm.ErrEmailInvalid
		lcr.Check.CheckResult = false

		return lcr
	}

	//check the account exists
	accExist, err := cr.AccountExists(ctx, userAccountCandidate.Email)
	if err != nil {
		lcr.Check.Error = err
		lcr.Check.CheckResult = false

		return lcr
	}

	if !accExist {
		lcr.Check.Error = aucm.ErrAccountNotExist
		lcr.Check.CheckResult = false

		return lcr
	}

	//check the user has access to this app (will always return error if access is denied
	//so we ignore the boolean and check for the error
	if _, err := cr.HasAccess(ctx, userAccountCandidate.Email, appName); err != nil {
		lcr.Check.Error = err
		lcr.Check.CheckResult = false

		return lcr
	}

	//then check the credentials
	pwdchk := cr.VerifyCredential(ctx, userAccountCandidate)
	if !pwdchk.Check.CheckResult || pwdchk.Check.Error != nil {
		lcr.Check.Error = pwdchk.Check.Error
		lcr.Check.CheckResult = false

		return lcr
	}

	//and get the authorisations token
	roletoken, err := cr.GetAccountRoleToken(ctx, pwdchk.UserAccountID)
	if err != nil {
		lcr.Check.Error = err
		lcr.Check.CheckResult = false

		return lcr
	}

	//store the login candidate
	lgid, err := cr.SaveLoginCandidate(ctx, pwdchk.UserAccountID, userAccountCandidate.Email, roletoken)
	if err != nil {
		lcr.Check.Error = err
		lcr.Check.CheckResult = false

		return lcr
	}

	//otherwise prepare return data
	lcr.Check.Error = nil
	lcr.Check.CheckResult = true
	lcr.IsTwoFactor = pwdchk.IsTwoFactor
	lcr.LoginID = lgid

	if EnvDebugOn {
		lblog.LogEvent("Core", "Login", "info", "end")
	}

	return lcr
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
func (cr *Core) ToggleTwoFactor(ctx context.Context, domain, userID string, period int32, toggle, qr bool) *aucm.ToggleOtpResult {
	if EnvDebugOn {
		lblog.LogEvent("Core", "ToggleTwoFactor", "info", "start")
	}

	chkr := &aucm.CheckResult{}
	otpr := &aucm.ToggleOtpResult{Check: chkr}

	//get the profile
	uacc, err := cr.Dm.GetLoginProfile(ctx, userID)

	if err != nil {
		otpr.Check.CheckResult = false
		otpr.Check.Error = err
		otpr.Check.CheckMessage = err.Error()

		return otpr
	}

	//if 2FA is on..
	if toggle {
		//exit if it is already on..
		if uacc.TwoFactorEnabled {
			otpr.Check.CheckResult = true
			otpr.Check.Error = nil
			otpr.Check.CheckMessage = "preenabled"

			return otpr
		}

		//otherwise generate a new otp key result
		rslt, err := otp.GenerateOtp(domain, uacc.Email, uint(period))

		if err != nil {
			otpr.Check.CheckResult = false
			otpr.Check.Error = err
			otpr.Check.CheckMessage = err.Error()

			return otpr
		}

		//turn the secret into an encrypted base64 string
		twofachash, err := cr.Kp.EncryptBytes(ctx, []byte(rslt.Secret))

		if err != nil {
			otpr.Check.CheckResult = false
			otpr.Check.Error = err
			otpr.Check.CheckMessage = err.Error()

			return otpr
		}

		//base64 the QR bytes
		qrc := base64.StdEncoding.EncodeToString(rslt.Img)

		//update the user account record
		uacc.TwoFactorEnabled = true
		uacc.TwoFactorHash = twofachash

		if qr {
			otpr.Qr = qrc
		}
	} else {
		//or switch off 2FA and clear the secret and qr
		uacc.TwoFactorEnabled = false
		uacc.TwoFactorHash = ""
	}

	//save the account
	_, err = cr.SaveAccount(ctx, uacc)

	if err != nil {
		otpr.Check.CheckResult = false
		otpr.Check.Error = err
		otpr.Check.CheckMessage = err.Error()

		return otpr
	}

	otpr.Check.CheckResult = true
	otpr.Check.Error = nil
	otpr.Check.CheckMessage = "success"

	return otpr
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
func (cr *Core) RequestReset(ctx context.Context, emailAddress, appName string) (string, error) {
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

	emconf, err := cr.Dm.StartAccountConfirmation(ctx, userid.UserAccountID, emailAddress, aucm.CredentialReset.String(), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationRdURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderAccount"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderName"))

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

	result, err := cr.SendMail(ctx, emconf, appName, true)

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

	emconf, err := cr.Dm.StartAccountConfirmation(ctx, userID, email, "registration", cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailAccountConfirmationRdURL"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderAccount"), cr.Bc.GetConfigValue(ctx, "EnvAuthMailSenderName"))

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
func (cr *Core) VerifyCredential(ctx context.Context, userAccountCandidate *aucm.UserAccountCandidate) *aucm.PasswordCheckResult {
	if EnvDebugOn {
		lblog.LogEvent("Core", "VerifyCredential", "info", "start")
	}

	apr := &aucm.PasswordCheckResult{Check: &aucm.CheckResult{}}

	//reject if this is an invalid email
	if !utils.EmailIsValid(userAccountCandidate.Email) {
		apr.Check.Error = aucm.ErrEmailInvalid
		apr.Check.CheckResult = false

		return apr
	}

	//see if the account exists..
	ctd, err := cr.Dm.GetAccountCount(ctx, userAccountCandidate.Email)

	if err != nil {
		apr.Check.Error = err
		apr.Check.CheckResult = false

		return apr
	}

	//if the count is zero then return
	if ctd == 0 {
		apr.Check.Error = aucm.ErrAccountNotLocated
		apr.Check.CheckResult = false

		return apr
	}

	//get the credential element of the account
	candidate, err := cr.Dm.GetAccountCredential(ctx, userAccountCandidate.Email)

	if err != nil {
		apr.Check.Error = err
		apr.Check.CheckResult = false

		return apr
	}

	//prep a current time
	currentTime := time.Now()

	//if the account is locked then return the error
	if candidate.LockoutEnd.After(currentTime) {
		apr.Check.Error = aucm.ErrAccountIsLocked
		apr.Check.CheckResult = false

		return apr
	}

	//now check the credentials match
	chk, err := utils.GetHashCompare(candidate.PasswordHash, userAccountCandidate.Password)

	//if there was an error..
	if err != nil {
		apr.Check.CheckResult = false
		apr.Check.Error = err

		//if the error is that the password was incorrect..
		if err == utils.ErrCredentialsNotCorrect {
			//save the failed login attempt
			lgerr := cr.Dm.SavedFailedLogin(ctx, userAccountCandidate.Email)

			if lgerr != nil {
				apr.Check.CheckResult = false
				apr.Check.Error = lgerr
			}
		}

		return apr
	}

	//we reach this point if the credential check was successful
	//if there were previous failed login attempts.. then reset the count.. because all is good now
	if candidate.AccessFailedCount > 0 {
		lgerr := cr.Dm.ResetFailedLogin(ctx, userAccountCandidate.Email)

		if lgerr != nil {
			apr.Check.CheckResult = false
			apr.Check.Error = lgerr

			return apr
		}
	}

	//record 2FA status
	apr.IsTwoFactor = candidate.TwoFactorEnabled
	apr.UserAccountID = candidate.UserAccountID

	//and finally prep the results
	if chk {
		apr.Check.CheckResult = chk
		apr.Check.Error = nil
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "VerifyCredential", "info", "end")
	}

	return apr
}

//VerifyOtp checks
func (cr *Core) VerifyOtp(ctx context.Context, otpCandidate *aucm.OtpCandidate) *aucm.OtpResult {
	if EnvDebugOn {
		lblog.LogEvent("Core", "VerifyOtp", "info", "start")
		lblog.LogEvent("Core", "VerifyOtp", "2FAOTP", otpCandidate.Otp)
	}

	lor := &aucm.OtpResult{Check: &aucm.CheckResult{}}

	if otpCandidate.Otp == "" {
		lor.Check.CheckResult = false
		lor.Check.Error = aucm.ErrOtpNotExist

		return lor
	}

	lc, err := cr.Dm.GetLoginCandidate(ctx, otpCandidate.LoginID)
	if err != nil {
		lor.Check.CheckResult = false
		lor.Check.Error = err

		return lor
	}

	//get the credential element of the account
	candidate, err := cr.Dm.GetAccountCredential(ctx, lc.Email)

	if err != nil {
		lor.Check.Error = err
		lor.Check.CheckResult = false

		return lor
	}

	//decrypt the secret
	secret, err := cr.Kp.DecryptString(ctx, candidate.TwoFactorHash)

	if err != nil {
		lor.Check.CheckResult = false
		lor.Check.Error = err

		return lor
	}

	//exit if the passcode was not valid
	if !otp.VerifyOtp(otpCandidate.Otp, secret) {
		lor.Check.CheckResult = false
		lor.Check.Error = otp.ErrPasscodeNotValid

		return lor
	}

	lor.Check.CheckResult = true
	lor.Check.CheckMessage = "passed"

	if EnvDebugOn {
		lblog.LogEvent("Core", "Login", "info", "end")
	}

	return lor
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

//SaveLoginCandidate saves a login record
func (cr *Core) SaveLoginCandidate(ctx context.Context, userID, email, roletoken string) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveLoginCandidate", "info", "start")
	}
	currentTime := time.Now()
	activatedTime := &time.Time{}

	lc := &aucm.LoginCandidate{
		UserAccountID: userID,
		Email:         email,
		RoleToken:     roletoken,
		Activated:     false,
		CreatedDate:   &currentTime,
		ActivatedDate: activatedTime,
	}

	logid, err := cr.Dm.SetLoginCandidate(ctx, lc)
	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("Core", "SaveLoginCandidate", "info", "end")
	}
	return logid, nil
}

//ActivateLoginCandidate activates the login candidate record
func (cr *Core) ActivateLoginCandidate(ctx context.Context, loginID string) (map[string]interface{}, error) {
	shdr := make(map[string]interface{})

	currentTime := time.Now()

	lc, err := cr.Dm.GetLoginCandidate(ctx, loginID)
	if err != nil {
		return nil, err
	}

	//check that the login candidate has not expired
	cd := *lc.CreatedDate
	if currentTime.Sub(cd) > (time.Minute * 5) {
		return nil, aucm.ErrLcExpired
	}

	//collect the map elements
	shdr[sess.ConstJwtID] = lc.SessionID
	shdr[sess.ConstJwtRole] = lc.RoleToken
	shdr[sess.ConstJwtAccID] = lc.UserAccountID
	shdr[sess.ConstJwtEml] = lc.Email

	//mark the record as active
	lc.Activated = true
	lc.ActivatedDate = &currentTime

	//and save back
	_, err = cr.Dm.SetLoginCandidate(ctx, lc)
	if err != nil {
		return nil, err
	}

	return shdr, nil
}
