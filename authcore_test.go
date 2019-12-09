package auth

import (
	"log"
	"testing"
	"time"

	lbcf "github.com/lidstromberg/config"
	kp "github.com/lidstromberg/keypair"
	sess "github.com/lidstromberg/session"
	stor "github.com/lidstromberg/storage"
	utils "github.com/lidstromberg/utils"

	sendgrid "github.com/sendgrid/sendgrid-go"
	"golang.org/x/net/context"
)

var appName = "{{appname}}"

func createNewCore(ctx context.Context) (AuthCore, error) {

	bc := lbcf.NewConfig(ctx)

	//load the config
	cfm1 := PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	//create a storage manager
	sm, err := stor.NewMgr(ctx, bc)

	if err != nil {
		log.Fatal(err)
	}

	//load the mailer config
	cfm2, err := LoadMailerConfig(ctx, sm, bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))

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

	uacc1 := &UserAccountCandidate{Email: "test_accountexists@here.com"}

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

	uacc2 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	result := svb.Register(ctx, uacc2, appName)
	if result.Check.Error != nil {
		t.Fatal(result.Check.Error)
	}

	t.Logf("Register confirm token: %s", result.ConfirmToken)
	t.Logf("Register accountid: %s", result.UserAccountID)
}
func Test_Login(t *testing.T) {
	ctx := context.Background()

	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header: %v", shdr1)
}
func Test_GetLoginProfile(t *testing.T) {
	ctx := context.Background()

	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	prof1, err := svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string), true)

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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	prof1, err := svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string), false)
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

	prof1, err = svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string), true)

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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	conftoken, err := svb.RequestReset(ctx, ulogin1.Email, appName)
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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr1[sess.ConstJwtAccID].(string), shdr1[sess.ConstJwtEml].(string), appName, false)
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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr1[sess.ConstJwtAccID].(string), shdr1[sess.ConstJwtEml].(string), appName, false)
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

	uacc2 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	result, err := svb.HasAccess(ctx, uacc2.Email, "noaccesstoapp")
	if err != nil && err != ErrAppRoleAccessDenied {
		t.Fatal(err)
	}

	if result {
		t.Fatal("account should not have app access")
	}
}
func Test_GetAccountRoleToken(t *testing.T) {
	ctx := context.Background()

	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header was %s", shdr1[sess.ConstJwtEml].(string))

	roletoken, err := svb.GetAccountRoleToken(ctx, shdr1[sess.ConstJwtAccID].(string))
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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("session header was returned %s", shdr1[sess.ConstJwtEml].(string))

	accapps, err := svb.GetAccountRole(ctx, shdr1[sess.ConstJwtAccID].(string))
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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	conftoken, err := svb.StartAccountConfirmation(ctx, shdr1[sess.ConstJwtAccID].(string), shdr1[sess.ConstJwtEml].(string), appName, false)
	if err != nil {
		t.Fatal(err)
	}

	if conftoken == "" {
		t.Fatal("conftoken is nil")
	}

	t.Logf("conftoken is %s", conftoken)

	currentTime := time.Now()
	expiryDate := time.Now().Add(24 * time.Hour)

	uac1 := UserAccountConfirmation{
		ConfirmToken:                conftoken,
		Email:                       shdr1[sess.ConstJwtEml].(string),
		UserAccountID:               shdr1[sess.ConstJwtAccID].(string),
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

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	uec := &UserEmailConfirm{
		Email:                       shdr1[sess.ConstJwtEml].(string),
		ConfirmToken:                utils.NewID(),
		ConfirmURL:                  "EnvAuthMailAccountConfirmationURL",
		EmailSender:                 "test_reglog@here.com",
		UserAccountConfirmationType: Registration.String(),
	}

	result, err := svb.SendMail(ctx, uec, appName, false)
	if err != nil {
		t.Fatal(err)
	}

	if !result {
		t.Fatal("failed to sendmail")
	}
}
func Test_SaveAccountApp(t *testing.T) {
	currentTime := time.Now()
	zeroTime := time.Time{}

	ctx := context.Background()
	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ulogin1 := &UserAccountCandidate{Email: "test_reglog@here.com", Password: "Pass1"}

	lgres := svb.Login(ctx, ulogin1, appName)
	if lgres.Check.Error != nil {
		t.Fatal(lgres.Check.Error)
	}

	if lgres.IsTwoFactor {
		t.Fatal("this is an otp account")
	}

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgres.LoginID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("sessid was returned %s", shdr1[sess.ConstJwtID].(string))

	uacc, err := svb.GetLoginProfile(ctx, shdr1[sess.ConstJwtAccID].(string), false)
	if err != nil {
		t.Fatal(err)
	}

	newUaccApp := &UserAccountApplication{}
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
func Test_SaveLoginCandidate(t *testing.T) {
	ctx := context.Background()

	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	lgid, err := svb.SaveLoginCandidate(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("LoginID : %s", lgid)
}
func Test_ActivateLoginCandidate(t *testing.T) {
	ctx := context.Background()

	svb, err := createNewCore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	lgid, err := svb.SaveLoginCandidate(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("LoginID : %s", lgid)

	shdr1, err := svb.ActivateLoginCandidate(ctx, lgid)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Header : %v", shdr1)
}
