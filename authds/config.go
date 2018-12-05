package authds

import (
	"log"
	"os"
	"strconv"

	lbcf "github.com/lidstromberg/config"

	"golang.org/x/net/context"
)

var (
	//EnvDebugOn controls verbose logging
	EnvDebugOn bool
	//EnvClientPool is the size of the client pool
	EnvClientPool int
)

//preflight checks that the incoming configuration map contains the required config elements for the datastore backend
func preflight(ctx context.Context, bc lbcf.ConfigSetting) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("Started AuthDs preflight..")

	cfm1 := preflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	if bc.GetConfigValue(ctx, "EnvDebugOn") == "" {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	if bc.GetConfigValue(ctx, "EnvClientPool") == "" {
		log.Fatal("Could not parse environment variable EnvClientPool")
	}

	if bc.GetConfigValue(ctx, "EnvAuthDsAccountKind") == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountKind")
	}

	if bc.GetConfigValue(ctx, "EnvAuthDsAccountNamespace") == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountNamespace")
	}

	if bc.GetConfigValue(ctx, "EnvAuthDsAccountConfirmKind") == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountConfirmKind")
	}

	if bc.GetConfigValue(ctx, "EnvAuthDsLoginKind") == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsLoginKind")
	}

	if bc.GetConfigValue(ctx, "EnvAuthGcpProject") == "" {
		log.Fatal("Could not parse environment variable EnvAuthGcpProject")
	}

	//set the debug value
	constlog, err := strconv.ParseBool(bc.GetConfigValue(ctx, "EnvDebugOn"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	EnvDebugOn = constlog

	//set the poolsize
	pl, err := strconv.ParseInt(bc.GetConfigValue(ctx, "EnvClientPool"), 10, 64)

	if err != nil {
		log.Fatal("Could not parse environment variable EnvClientPool")
	}

	EnvClientPool = int(pl)

	log.Println("..Finished AuthDs preflight.")
}

//preflightConfigLoader loads the session config vars
func preflightConfigLoader() map[string]string {
	cfm := make(map[string]string)

	/**********************************************************************
	* DATASTORE ENV SETTINGS
	**********************************************************************/
	//EnvAuthDsAccountKind is the account entity
	cfm["EnvAuthDsAccountKind"] = os.Getenv("LBAUTH_KD_ACC")
	//EnvAuthDsAccountNamespace is the datastore namespace used for authentication
	cfm["EnvAuthDsAccountNamespace"] = os.Getenv("LBAUTH_ACCNAMESP")
	//EnvAuthDsAccountConfirmKind is the account confirmation token entity
	cfm["EnvAuthDsAccountConfirmKind"] = os.Getenv("LBAUTH_KD_ACCCNF")
	//EnvAuthDsLoginKind is the login candidate entity
	cfm["EnvAuthDsLoginKind"] = os.Getenv("LBAUTH_KD_LOGIN")
	//EnvClientPool is the client poolsize
	cfm["EnvClientPool"] = os.Getenv("LBAUTH_CLIPOOL")

	if cfm["EnvAuthDsAccountKind"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountKind")
	}

	if cfm["EnvAuthDsAccountNamespace"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountNamespace")
	}

	if cfm["EnvAuthDsAccountConfirmKind"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsAccountConfirmKind")
	}

	if cfm["EnvAuthDsLoginKind"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthDsLoginKind")
	}

	if cfm["EnvClientPool"] == "" {
		log.Fatal("Could not parse environment variablex EnvClientPool")
	}

	return cfm
}
