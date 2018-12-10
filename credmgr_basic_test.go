package auth

import (
	"log"
	"testing"

	lbcf "github.com/lidstromberg/config"
	stor "github.com/lidstromberg/storage"

	context "golang.org/x/net/context"
)

func Test_DataRepoConnect(t *testing.T) {
	ctx := context.Background()

	bc := lbcf.NewConfig(ctx)

	//run preflight checks
	cfm1 := PreflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	//create a storage manager
	sm, err := stor.NewStorMgr(ctx, bc)

	if err != nil {
		log.Fatal(err)
	}

	//load the mailer config
	cfm2, err := LoadMailerConfig(ctx, sm, bc.GetConfigValue(ctx, "EnvAuthGcpBucket"), bc.GetConfigValue(ctx, "EnvMailerFile"))

	if err != nil {
		t.Log(err)
		t.Fatal("Could not load from environment variable EnvMailerFile")
	}

	bc.LoadConfigMap(ctx, cfm2)

	//NewDsCredentialMgr creates a datastore client.. attempt to create a transaction.. if connectivity is bad, then this will fail
	cm, err := NewDsCredentialMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}

	tx, err := cm.dsclient.NewTransaction(ctx)

	if err != nil {
		t.Fatal(err)
	}

	tx.Rollback()
}
