package authpg

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

	cfm2, err := aucm.LoadMailerConfig(ctx, bc.GetConfigValue(ctx, "EnvAuthKPType"), bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))
	if err != nil {
		t.Fatal("Could not load from environment variable EnvMailerFile")
	}

	bc.LoadConfigMap(ctx, cfm2)

	//NewPgCredentialMgr runs a ping against the db.. if connectivity is bad, then this will fail
	_, err = NewPgCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}
}
