package authpg

import (
	"log"
	"os"
	"strconv"

	lbcf "github.com/lidstromberg/config"

	context "golang.org/x/net/context"
)

var (
	//EnvDebugOn controls verbose logging
	EnvDebugOn bool
)

//preflight checks that the incoming configuration map contains the required config elements for the datastore backend
func preflight(ctx context.Context, bc lbcf.ConfigSetting) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("Started AuthPg preflight..")

	cfm1 := preflightConfigLoader()
	bc.LoadConfigMap(ctx, cfm1)

	if bc.GetConfigValue(ctx, "EnvDebugOn") == "" {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	if bc.GetConfigValue(ctx, "EnvAuthSQLDataSourceType") == "" {
		log.Fatal("Could not parse environment variable EnvAuthSQLDataSourceType")
	}

	if bc.GetConfigValue(ctx, "EnvAuthSQLConnectionString") == "" {
		log.Fatal("Could not parse environment variable EnvAuthSQLConnectionString")
	}

	//set the debug value
	constlog, err := strconv.ParseBool(bc.GetConfigValue(ctx, "EnvDebugOn"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	EnvDebugOn = constlog

	log.Println("..Finished AuthPg preflight.")
}

//preflightConfigLoader loads the session config vars
func preflightConfigLoader() map[string]string {
	cfm := make(map[string]string)

	/**********************************************************************
	* POSTGRES ENV SETTINGS
	**********************************************************************/
	//EnvAuthSQLDataSourceType is the sql connection type
	cfm["EnvAuthSQLDataSourceType"] = os.Getenv("LBAUTH_SQLDST")
	//EnvAuthSQLConnectionString is the sql connection details
	cfm["EnvAuthSQLConnectionString"] = os.Getenv("LBAUTH_SQLCNX")

	if cfm["EnvAuthSQLDataSourceType"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthSQLDataSourceType")
	}

	if cfm["EnvAuthSQLConnectionString"] == "" {
		log.Fatal("Could not parse environment variable EnvAuthSQLConnectionString")
	}

	return cfm
}
