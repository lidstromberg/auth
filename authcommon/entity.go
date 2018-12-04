package authcommon

import (
	"time"
)

//UserAccountCredential represents the fragment of the user account record which is used
//to verify a login attempt
type UserAccountCredential struct {
	UserAccountID     string     `json:"useraccountid" datastore:"useraccountid"`
	PasswordHash      string     `json:"passwordhash" datastore:"passwordhash"`
	TwoFactorEnabled  bool       `json:"twofactorenabled" datastore:"twofactorenabled"`
	TwoFactorHash     string     `json:"twofactorhash" datastore:"twofactorhash"`
	LockoutEnabled    bool       `json:"lockoutenabled" datastore:"lockoutenabled"`
	AccessFailedCount int        `json:"accessfailedcount" datastore:"accessfailedcount"`
	LockoutEnd        *time.Time `json:"lockoutend,omitempty" datastore:"lockoutend"`
}

//EmailCandidate represents the user supplied text email
type EmailCandidate struct {
	Email string `json:"email"`
}

//UserAccountCandidate represents the user supplied text email and password
type UserAccountCandidate struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

//OtpCandidate represents the user supplied text email and otp
type OtpCandidate struct {
	Email string `json:"email"`
	Otp   string `json:"otp"`
}

//CheckResult represents information regarding a data search/save outcome
type CheckResult struct {
	CheckResult  bool   `json:"checkresult"`
	CheckMessage string `json:"checkmessage"`
	Error        error  `json:"-"`
}

//LoginCheckResult returns the state of the account
type LoginCheckResult struct {
	Check    *CheckResult `json:"check"`
	IsLocked bool         `json:"islocked"`
}

//PasswordCheckResult represents a set of return values from a password check
type PasswordCheckResult struct {
	Check       *CheckResult `json:"check"`
	IsTwoFactor bool         `json:"istwofactor"`
}

//RegisterCheckResult represents a set of return values from a register attempt
type RegisterCheckResult struct {
	Check        *CheckResult `json:"check"`
	ConfirmToken string       `json:"confirmtoken"`
}

//LoginOtpResult returns the otp result
type LoginOtpResult struct {
	Check *CheckResult `json:"check"`
}

//ToggleOtpResult represents the return values from a 2FA toggle attempt
type ToggleOtpResult struct {
	Check *CheckResult `json:"check"`
	Qr    string       `json:"qr"`
}

//UserAccountPasswordChange represents the fragment of the user account record which is required
//to implement a password change (should we be using sessionid here instead?)
type UserAccountPasswordChange struct {
	UserAccountID string `json:"useraccountid"`
	Password      string `json:"password"`
}

//SystemDefault represents a setting for the auth service
type SystemDefault struct {
	ItemKey   string `json:"itemkey" datastore:"itemkey"`
	ItemValue string `json:"itemvalue" datastore:"itemvalue"`
}

//SystemDefaultCheck represents the return values from a system default retrieval attempt
type SystemDefaultCheck struct {
	Check *CheckResult   `json:"check"`
	Sd    *SystemDefault `json:"sd"`
}

//UserAccount represents the full user account
type UserAccount struct {
	UserAccountID        string                    `json:"useraccountid" datastore:"useraccountid"`
	Email                string                    `json:"email" datastore:"email"`
	PasswordHash         string                    `json:"passwordhash" datastore:"passwordhash"`
	EmailConfirmed       bool                      `json:"emailconfirmed" datastore:"emailconfirmed"`
	LockoutEnabled       bool                      `json:"lockoutenabled" datastore:"lockoutenabled"`
	AccessFailedCount    int                       `json:"accessfailedcount" datastore:"accessfailedcount"`
	LockoutEnd           *time.Time                `json:"lockoutend,omitempty" datastore:"lockoutend"`
	PhoneNumber          string                    `json:"phonenumber" datastore:"phonenumber"`
	PhoneNumberConfirmed bool                      `json:"phonenumberconfirmed" datastore:"phonenumberconfirmed,noindex"`
	TwoFactorEnabled     bool                      `json:"twofactorenabled" datastore:"twofactorenabled"`
	TwoFactorHash        string                    `json:"twofactorhash" datastore:"twofactorhash"`
	IsActive             bool                      `json:"isactive" datastore:"isactive"`
	IsLockedForEdit      bool                      `json:"islockedforedit" datastore:"islockedforedit"`
	Scopes               []*UserAccountApplication `json:"scopes" datastore:"scopes"`
	CreatedDate          *time.Time                `json:"createddate,omitempty" datastore:"createddate"`
	RetiredDate          *time.Time                `json:"retireddate,omitempty" datastore:"retireddate"`
	LastTouched          *time.Time                `json:"lasttouched,omitempty" datastore:"lasttouched"`
}

//UserAccountApplication represents the list of accessible applications for an account
type UserAccountApplication struct {
	ApplicationName string     `json:"applicationname" datastore:"applicationname"`
	IsActive        bool       `json:"isactive" datastore:"isactive"`
	CreatedDate     *time.Time `json:"createddate,omitempty" datastore:"createddate"`
	RetiredDate     *time.Time `json:"retireddate,omitempty" datastore:"retireddate"`
}

//UserEmailConfirm represents the subset of information required for a user to confirm a registered account
type UserEmailConfirm struct {
	Email                       string `json:"email" datastore:"email"`
	ConfirmToken                string `json:"confirmtoken" datastore:"confirmtoken"`
	ConfirmURL                  string `json:"confirmurl" datastore:"confirmurl"`
	UserAccountConfirmationType string `json:"userconfirmationtype" datastore:"userconfirmationtype"`
	EmailSender                 string `json:"emailsender" datastore:"emailsender"`
	EmailSenderName             string `json:"emailsendername" datastore:"emailsendername"`
}

//UserAccountConfirmation represents the persisted account confirmation data
type UserAccountConfirmation struct {
	ConfirmToken                string     `json:"confirmtoken" datastore:"confirmtoken"`
	Email                       string     `json:"email" datastore:"email"`
	UserAccountID               string     `json:"useraccountid" datastore:"useraccountid"`
	TokenUsed                   bool       `json:"tokenused" datastore:"tokenused"`
	UserAccountConfirmationType string     `json:"useraccountconfirmationtype" datastore:"useraccountconfirmationtype"`
	RedirectLink                string     `json:"redirectlink" datastore:"redirectlink"`
	CreatedDate                 *time.Time `json:"createddate,omitempty" datastore:"createddate"`
	ExpiryDate                  *time.Time `json:"expirydate,omitempty" datastore:"expirydate"`
	ActivatedDate               *time.Time `json:"activateddate,omitempty" datastore:"activateddate"`
}

//UserAccountConfirmationResult represents the returned result from a confirmation action
type UserAccountConfirmationResult struct {
	Result                      bool   `json:"result" datastore:"result"`
	UserAccountConfirmationType string `json:"useraccountconfirmationtype" datastore:"useraccountconfirmationtype"`
	RedirectLink                string `json:"redirectlink" datastore:"redirectlink"`
}

//UserAccountConfirmationType enum for account confirmations
type UserAccountConfirmationType int

//Registration defines the types of available UserAccountConfirmation
const (
	Registration = UserAccountConfirmationType(iota)
	CredentialReset
)

func (uct UserAccountConfirmationType) String() string {
	return [...]string{"registration", "credentialreset"}[uct]
}
