package auth

import (
	"log"
	"strconv"

	aucm "github.com/lidstromberg/auth/authcommon"
	lbcf "github.com/lidstromberg/config"
	stor "github.com/lidstromberg/storage"

	"golang.org/x/net/context"
)

var (
	//EnvDebugOn controls verbose logging
	EnvDebugOn bool
)

//preflight config checks
func preflight(ctx context.Context, bc lbcf.ConfigSetting) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("Started AuthCore preflight..")

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

	//set the debug value
	constlog, err := strconv.ParseBool(bc.GetConfigValue(ctx, "EnvDebugOn"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	EnvDebugOn = constlog

	log.Println("..Finished AuthCore preflight.")
}
