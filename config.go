package auth

import (
	"log"
	"os"
	"strconv"

	lbcf "github.com/lidstromberg/config"
	stor "github.com/lidstromberg/storage"

	"golang.org/x/net/context"
)

var (
	//EnvDebugOn controls verbose logging
	EnvDebugOn bool
	//EnvClientPool is the size of the client pool
	EnvClientPool int
)

//preflight config checks
func preflight(ctx context.Context, bc lbcf.ConfigSetting) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("Started AuthCore preflight..")

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

	//set the debug value
	constlog, err := strconv.ParseBool(bc.GetConfigValue(ctx, "EnvDebugOn"))
	if err != nil {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	EnvDebugOn = constlog

	log.Println("..Finished AuthCore preflight.")
}

//PreflightConfigLoader loads the config vars
func PreflightConfigLoader() map[string]string {
	cfm := make(map[string]string)

	/**********************************************************************
	* BASE AUTH ENV SETTINGS
	**********************************************************************/
	//EnvDebugOn is the debug setting
	cfm["EnvDebugOn"] = os.Getenv("LB_DEBUGON")
	//EnvMailerType is the location of the mail template file (local/bucket)
	cfm["EnvMailerType"] = os.Getenv("LBAUTH_MAILERTYPE")
	//EnvMailerFile is the mail template file
	cfm["EnvMailerFile"] = os.Getenv("LBAUTH_MAILERFILE")
	//EnvSendMailKey is the sendmail api key
	cfm["EnvSendMailKey"] = os.Getenv("SENDGRID_API_KEY")
	//EnvAuthGcpProject is the cloud project to target
	cfm["EnvAuthGcpProject"] = os.Getenv("LBAUTH_GCP_PROJECT")
	//EnvAuthGcpBucket is the cloud bucket to target
	cfm["EnvAuthGcpBucket"] = os.Getenv("LBAUTH_GCP_BUCKET")
	//EnvAuthAppRoleDelim is the delimiter character used when joining the user app roles in the jwt
	cfm["EnvAuthAppRoleDelim"] = os.Getenv("LBAUTH_APPROLEDELIM")
	//EnvAuthDsType is the type of datastore (postgres/datastore)
	cfm["EnvAuthDsType"] = os.Getenv("LBAUTH_DSTYPE")

	if cfm["EnvDebugOn"] == "" {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	if cfm["EnvMailerType"] == "" {
		log.Fatal("Could not parse environment variable EnvMailerType")
	}

	if cfm["EnvMailerFile"] == "" {
		log.Fatal("Could not parse environment variable EnvMailerFile")
	}

	if cfm["EnvSendMailKey"] == "" {
		log.Fatal("Could not parse environment variable EnvSendMailKey")
	}

	if cfm["EnvAuthGcpProject"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthGcpProject")
	}

	if cfm["EnvAuthGcpBucket"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthGcpBucket")
	}

	if cfm["EnvAuthAppRoleDelim"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthAppRoleDelim")
	}

	if cfm["EnvAuthDsType"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsType")
	}

	return cfm
}
