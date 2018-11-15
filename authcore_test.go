package auth

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
	"time"

	aucm "github.com/lidstromberg/auth/authcommon"
	utils "github.com/lidstromberg/auth/utils"
	lbcf "github.com/lidstromberg/config"
	kp "github.com/lidstromberg/keypair"
	sess "github.com/lidstromberg/session"
	stor "github.com/lidstromberg/storage"

	sendgrid "github.com/sendgrid/sendgrid-go"
	"golang.org/x/net/context"
)

var appName = "issuelog"

func createNewCore(ctx context.Context) (AuthCore, error) {

	bc := lbcf.NewConfig(ctx)

	//load the config
	cfm1 := aucm.PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	//create a storage manager
	sm, err := stor.NewStorMgr(ctx, bc)

	if err != nil {
		log.Fatal(err)
	}

	//load the mailer config
	cfm2, err := aucm.LoadMailerConfig(ctx, sm, bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))

	if err != nil {
		log.Fatal(err)
	}

	bc.LoadConfigMap(ctx, cfm2)

	//create a keypair
	kpr, err := kp.NewKeyPair(ctx, bc)

	if err != nil {
		return nil, err
	}

	//create a mail client
	mc := sendgrid.NewSendClient(bc.GetConfigValue(ctx, "EnvSendMailKey"))

	svb, err := NewCoreCredentialMgr(ctx, bc, kpr, mc)

	if err != nil {
		return nil, err
	}

	if svb == nil {
		return nil, err
	}

	return svb, nil
}
func Test_AccountExists(t *testing.T) {
	ctx := context.Background()
	cr1, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	uacc1 := &aucm.UserAccountCandidate{Email: "test_accountexists@here.com"}

	result, err := cr1.AccountExists(ctx, uacc1.Email)

	if err != nil {
		t.Fatal(err)
	}

	if result {
		t.Fatal("Account exists but it shouldn't (yet). Do you need to reset the data repo?")
	}

	t.Logf("account exists: %t", result)
}
func Test_Register(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	uacc2 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}
	shdr1, err := svb.Register(ctx, uacc2, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Register account: %s", shdr1[sess.ConstJwtAccID].(string))
}
func Test_Login(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr)
}
func Test_GetLoginProfile(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr1, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	prof1, err := svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if prof1 == nil {
		t.Fatal("prof1 is nil")
	}

	t.Logf("User profile email: %s", prof1.Email)
}
func Test_SaveAccount(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr1, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	prof1, err := svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if prof1 == nil {
		t.Fatal("prof1 1st is nil")
	}

	var firstPhone = prof1.PhoneNumber

	t.Logf("User phone 1st: %s", firstPhone)

	prof1.PhoneNumber = "456"

	userid, err := svb.SaveAccount(ctx, prof1)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("returned userid is %s", userid)

	prof1, err = svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if prof1 == nil {
		t.Fatal("prof1 2nd is nil")
	}

	t.Logf("User phone 2nd: %s", prof1.PhoneNumber)

	if firstPhone == prof1.PhoneNumber {
		t.Fatal("1st and 2nd phone numbers were the same")
	}
}
func Test_RequestReset(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	conftoken, err := svb.RequestReset(ctx, ulogin1.Email, appName, false)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("credreset conftoken %s", conftoken)
}
func Test_StartAccountConfirmation(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_startacconf@here.com", Password: "Pass1"}

	shdr, err := svb.Register(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr)

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr[sess.ConstJwtAccID].(string), shdr[sess.ConstJwtEml].(string), appName, false)

	if err != nil {
		t.Fatal(err)
	}

	if conftoken == "" {
		t.Fatal("conftoken is nil")
	}

	t.Logf("conftoken is %s", conftoken)
}
func Test_FinishAccountConfirmation(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_finishacconf@here.com", Password: "Pass1"}
	shdr, err := svb.Register(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Register account: %s", shdr[sess.ConstJwtAccID].(string))

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr[sess.ConstJwtAccID].(string), shdr[sess.ConstJwtEml].(string), appName, false)

	if err != nil {
		t.Fatal(err)
	}

	if conftoken == "" {
		t.Fatal("emconf is nil")
	}

	t.Logf("conftoken: %s", conftoken)

	confres, err := svb.FinishAccountConfirmation(ctx, conftoken)

	if err != nil {
		t.Fatal(err)
	}

	if !confres.Result {
		t.Fatal("failed to complete registration cycle")
	}

	t.Logf("redirect link %s", confres.RedirectLink)
}
func Test_HasAccess(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	uacc2 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	result, err := svb.HasAccess(ctx, uacc2.Email, appName)

	if err != nil && err != aucm.ErrAppRoleAccessDenied {
		t.Fatal(err)
	}

	if result {
		t.Fatal("account should not have app access yet")
	}
}
func Test_GetAccountRoleToken(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("session header was %s", shdr[sess.ConstJwtEml].(string))
	}

	roletoken, err := svb.GetAccountRoleToken(ctx, shdr[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("roletoken was %s", roletoken)
}
func Test_GetAccountRole(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("session header was returned %s", shdr[sess.ConstJwtEml].(string))
	}

	accapps, err := svb.GetAccountRole(ctx, shdr[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if accapps == nil {
		t.Fatal("accapps is nil")
	}

	for index, item := range accapps {
		t.Logf("application %d name is %s", index, item.ApplicationName)
	}
}
func Test_VerifyCredential(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	check := svb.VerifyCredential(ctx, ulogin1)

	if check.Check.Error != nil {
		t.Fatal(check.Check.Error)
	}

	if !check.Check.CheckResult {
		t.Fatal("Good password did not validate")
	} else {
		t.Log("Good password validated")
	}

	ulogin1.Password = "Pass99"

	check = svb.VerifyCredential(ctx, ulogin1)

	if check.Check.Error != nil {
		if check.Check.Error == utils.ErrCredentialsNotCorrect {
			t.Log("Bad password correctly rejected")
		} else {
			t.Fatal(check.Check.Error)
		}
	}

	if check.Check.CheckResult {
		t.Fatal("Bad password validated")
	}
}
func Test_SaveEmailConfirmation(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_emailconf@here.com", Password: "Pass1"}

	shdr, err := svb.Register(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr)

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr[sess.ConstJwtAccID].(string), shdr[sess.ConstJwtEml].(string), appName, false)

	if err != nil {
		t.Fatal(err)
	}

	if conftoken == "" {
		t.Fatal("conftoken is nil")
	}

	t.Logf("conftoken is %s", conftoken)

	currentTime := time.Now()
	expiryDate := time.Now().Add(24 * time.Hour)

	uac1 := aucm.UserAccountConfirmation{
		ConfirmToken:                conftoken,
		Email:                       shdr[sess.ConstJwtEml].(string),
		UserAccountID:               shdr[sess.ConstJwtAccID].(string),
		TokenUsed:                   false,
		UserAccountConfirmationType: "registration",
		RedirectLink:                "link",
		CreatedDate:                 &currentTime,
		ActivatedDate:               &currentTime,
		ExpiryDate:                  &expiryDate,
	}

	confres, err := svb.SaveEmailConfirmation(ctx, &uac1)

	if err != nil {
		t.Fatal(err)
	}

	if confres == nil {
		t.Fatal("confres is nil")
	}

	t.Logf("confred is %v", confres)
}
func Test_SendMail(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr)

	uec := &aucm.UserEmailConfirm{
		Email:                       shdr[sess.ConstJwtEml].(string),
		ConfirmToken:                utils.NewID(),
		ConfirmURL:                  "EnvAuthMailAccountConfirmationURL",
		EmailSender:                 "EnvAuthMailSenderAccount",
		UserAccountConfirmationType: aucm.Registration.String(),
	}

	result, err := svb.SendMail(ctx, uec, appName, false)

	if err != nil {
		t.Fatal(err)
	}

	if !result {
		t.Fatal("failed to sendmail")
	}
}

//broader logic tests..
func Test_SaveAccountApp(t *testing.T) {
	currentTime := time.Now()
	zeroTime := time.Time{}

	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}
	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("sessid was returned %s", shdr[sess.ConstJwtID].(string))
	}

	uacc, err := svb.GetLoginProfile(ctx, shdr[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	newUaccApp := &aucm.UserAccountApplication{}
	newUaccApp.ApplicationName = "addedapp"
	newUaccApp.CreatedDate = &currentTime
	newUaccApp.IsActive = true
	newUaccApp.RetiredDate = &zeroTime

	var isreplace bool

	scopes := uacc.Scopes

	//if this is an existing app then replace the current data
	for index, item := range scopes {
		currentitem := item
		if currentitem.ApplicationName == newUaccApp.ApplicationName {
			currentitem.IsActive = newUaccApp.IsActive
			currentitem.RetiredDate = newUaccApp.RetiredDate
			scopes[index] = currentitem
			isreplace = true
		}
	}

	if !isreplace {
		scopes = append(scopes, newUaccApp)
	}

	uacc.Scopes = scopes

	userid, err := svb.SaveAccount(ctx, uacc)

	if err != nil {
		t.Fatal(err)
	}

	if userid == "" {
		t.Fatal("new accapp did not save")
	}

	t.Logf("userid: %s", userid)
}
func Test_VerifyCredential_CauseLockout(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	//first register the account to test
	ulogin1 := &aucm.UserAccountCandidate{Email: "test_causelockout@here.com", Password: "Pass1"}
	shdr, err := svb.Register(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Register account: %s", shdr[sess.ConstJwtAccID].(string))

	//wrong password.. should be Pass1
	ulogin1.Password = "Pass99"

	//lockout should be caused on the 4th attempt
	for i := 1; i < 5; i++ {
		localI := i
		check := svb.VerifyCredential(ctx, ulogin1)

		if check.Check.Error != nil {
			//the credentials are bad, so we should always hit this outcome until the account locks
			if check.Check.Error == utils.ErrCredentialsNotCorrect {
				t.Logf("Bad password correctly rejected: %d", localI)
			} else if check.Check.Error == aucm.ErrAccountIsLocked {
				//if the account is locked, check that this message occurred on the 4th attempt
				//because the user should have three attempts to get the password right
				if localI != 4 {
					t.Fatalf("Account incorrectly locked out on bad attempt %d", localI)
				} else {
					t.Logf("Account locked out on bad attempt %d", localI)
					break
				}
			} else {
				t.Fatal(check.Check.Error)
			}
		}

		if localI > 4 {
			t.Fatalf("Account failed to lock out on 4th bad attempt: %d", localI)
		}
	}
}
func Test_Login_OnLockedAccount(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	//first register the account to test
	ulogin1 := &aucm.UserAccountCandidate{Email: "test_islockedout@here.com", Password: "Pass1"}
	shdr, err := svb.Register(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Register account: %s", shdr[sess.ConstJwtAccID].(string))

	//wrong password.. should be Pass1
	ulogin1.Password = "Pass99"

	//lockout should be caused on the 4th attempt
	for i := 1; i < 5; i++ {
		localI := i
		check := svb.VerifyCredential(ctx, ulogin1)

		if check.Check.Error != nil {
			//the credentials are bad, so we should always hit this outcome until the account locks
			if check.Check.Error == utils.ErrCredentialsNotCorrect {
				t.Logf("Bad password correctly rejected: %d", localI)
			} else if check.Check.Error == aucm.ErrAccountIsLocked {
				//if the account is locked, check that this message occurred on the 4th attempt
				//because the user should have three attempts to get the password right
				if localI != 4 {
					t.Fatalf("Account incorrectly locked out on bad attempt %d", localI)
				} else {
					t.Logf("Account locked out on bad attempt %d", localI)
					break
				}
			} else {
				t.Fatal(check.Check.Error)
			}
		}

		if localI > 4 {
			t.Fatalf("Account failed to lock out on 4th bad attempt: %d", localI)
		}
	}

	_, err = svb.Login(ctx, ulogin1, appName)

	if err != nil {
		if err != aucm.ErrAccountIsLocked {
			t.Fatal(err)
		} else if err == aucm.ErrAccountIsLocked {
			t.Log("login correctly failed because the account is locked")
			return
		}
	}

	t.Fatal("login on locked account was not detected")
}
func Test_Login_LockoutExpired(t *testing.T) {
	//You may need to manually set back the lockoutend value on the backend data repo for this test!
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_islockedout@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		if err == aucm.ErrAccountIsLocked {
			t.Fatal("login incorrectly failed because the account is locked")
		} else {
			t.Fatal(err)
		}
	}

	t.Logf("session header: %v", shdr)
}
func Test_SaveTwoFactor(t *testing.T) {
	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	prof1, err := svb.GetLoginProfile(ctx, shdr[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if prof1 == nil {
		t.Fatal("prof1 1st is nil")
	}

	var tf = prof1.TwoFactorEnabled

	t.Logf("Two factor 1st: %t", tf)

	rslt := svb.ToggleTwoFactor(ctx, "localhost", shdr[sess.ConstJwtAccID].(string), 30, true, true)

	if rslt.Check.Error != nil {
		t.Fatal(rslt.Check.Error)
	}

	data, err := base64.StdEncoding.DecodeString(rslt.Qr)

	if err != nil {
		t.Fatal(err)
	}

	ioutil.WriteFile("qr-code.png", data, 0644)

	prof1, err = svb.GetLoginProfile(ctx, shdr[sess.ConstJwtAccID].(string))

	if err != nil {
		t.Fatal(err)
	}

	if prof1 == nil {
		t.Fatal("prof1 2nd is nil")
	}

	t.Logf("Two factor 2nd: %t", prof1.TwoFactorEnabled)
	t.Logf("Two factor hash 2nd: %s", prof1.TwoFactorHash)

	if tf == prof1.TwoFactorEnabled {
		t.Fatal("1st and 2nd twofactor values were the same")
	}
}
func Test_ValidateTwoFactor(t *testing.T) {
	/**********************************
	  This one requires some manual intervention.
	  Test_SaveTwoFactor will output a QR image.
	  You will need an authenticator app (such as Google Authenticator) to scan the QR image
	  Use the authenticator app to then obtain a 2FA code and place the code in the Otp field within this test
	  You should then be able to run this test
	  Note that your QR image scan/device and test should run within the same timezone (they should all show the same time roughly)
	  Otherwise the Otp code is likely to fail
	  **********************************/

	ctx := context.Background()
	svb, err := createNewCore(ctx)

	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &aucm.UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	chk := svb.LoginCheck(ctx, ulogin1.Email)

	if chk.Check.Error != nil {
		t.Fatal(chk.Check.Error)
	}

	if chk.IsLocked {
		t.Fatal("account is locked")
	}

	if !chk.IsTwoFactor {
		t.Fatal("account is not 2FA")
	}

	//replace this code with the number from your authenticator app
	ulogin1.Otp = "793687"

	shdr, err := svb.Login(ctx, ulogin1, appName)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr)
}
