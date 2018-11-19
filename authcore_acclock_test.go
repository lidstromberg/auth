package auth

import (
	"testing"

	aucm "github.com/lidstromberg/auth/authcommon"
	utils "github.com/lidstromberg/auth/utils"
	sess "github.com/lidstromberg/session"
	"golang.org/x/net/context"
)

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
