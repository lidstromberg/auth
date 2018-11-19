package auth

import (
	"encoding/base64"
	"io/ioutil"
	"testing"

	aucm "github.com/lidstromberg/auth/authcommon"
	sess "github.com/lidstromberg/session"
	"golang.org/x/net/context"
)

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
