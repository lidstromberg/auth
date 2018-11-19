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

	//NewPgCredentialMgr runs a ping against the db.. if connectivity is bad, then this will fail
	_, err := NewPgCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}
}
