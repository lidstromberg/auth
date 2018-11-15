package authds

import (
	"testing"

	aucm "github.com/lidstromberg/auth/authcommon"
	lbcf "github.com/lidstromberg/config"

	context "golang.org/x/net/context"
)

func Test_DataRepoConnect(t *testing.T) {
	ctx := context.Background()

	bc := lbcf.NewConfig(ctx)

	//run preflight checks
	cfm1 := aucm.PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	cfm2, err := aucm.LoadMailerConfig(ctx, bc.GetConfigValue(ctx, "EnvMailerType"), bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))
	if err != nil {
		t.Fatal("Could not load from environment variable EnvMailerFile")
	}

	bc.LoadConfigMap(ctx, cfm2)

	//NewDsCredentialMgr creates a datastore client.. attempt to create a transaction.. if connectivity is bad, then this will fail
	cm, err := NewDsCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}

	tx, err := cm.CmDsClient.NewTransaction(ctx)

	if err != nil {
		t.Fatal(err)
	}

	tx.Rollback()
}
func Test_SetSystemDefault(t *testing.T) {
	ctx := context.Background()

	bc := lbcf.NewConfig(ctx)

	//run preflight checks
	cfm1 := aucm.PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	cfm2, err := aucm.LoadMailerConfig(ctx, bc.GetConfigValue(ctx, "EnvAuthKPType"), bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))
	if err != nil {
		t.Fatal("Could not load from environment variable EnvMailerFile")
	}

	bc.LoadConfigMap(ctx, cfm2)

	cm, err := NewDsCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}

	err = cm.SaveSystemDefault(ctx, "LBAUTH_ML_REG_PLN", "Please confirm your registration. Type this URL into a web browser: %s%s	")

	if err != nil {
		t.Fatal(err)
	}
}
func Test_GetSystemDefault(t *testing.T) {
	ctx := context.Background()

	bc := lbcf.NewConfig(ctx)

	//run preflight checks
	cfm1 := aucm.PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	cfm2, err := aucm.LoadMailerConfig(ctx, bc.GetConfigValue(ctx, "EnvAuthKPType"), bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))
	if err != nil {
		t.Fatal("Could not load from environment variable EnvMailerFile")
	}

	bc.LoadConfigMap(ctx, cfm2)

	cm, err := NewDsCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}

	sd, err := cm.GetSystemDefault(ctx, "LBAUTH_ML_REG_PLN")

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("system default key: %s", sd.ItemKey)
	t.Logf("system default: %s", sd.ItemValue)
}
