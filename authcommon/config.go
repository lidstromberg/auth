package authcommon

import (
	"context"
	"encoding/json"
	"log"
	"os"

	stor "github.com/lidstromberg/storage"
)

//LoadMailerConfig loads the mailer config file
func LoadMailerConfig(ctx context.Context, sm *stor.StorMgr, bucketName, fileName string) (map[string]string, error) {
	cfm := make(map[string]string)

	type mailerData struct {
		MlSender          string `json:"mlsender"`
		MlSenderName      string `json:"mlsendername"`
		MlConfirm         string `json:"mlconfirm"`
		MlConfirmRedirect string `json:"mlconfirmredirect"`
		MlRegSubject      string `json:"mlregsubject"`
		MlRegTxt          string `json:"mlregtxt"`
		MlRegHTML         string `json:"mlreghtml"`
		MlCredSubject     string `json:"mlcredsubject"`
		MlCredTxt         string `json:"mlcredtxt"`
		MlCredHTML        string `json:"mlcredhtml"`
	}

	var md mailerData

	//GCS read (otherwise local read)
	filebytes, err := sm.GetBucketFileData(ctx, bucketName, fileName)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(filebytes, &md)

	if err != nil {
		return nil, err
	}

	cfm["EnvAuthMailSenderAccount"] = md.MlSender
	cfm["EnvAuthMailSenderName"] = md.MlSenderName
	cfm["EnvAuthMailAccountConfirmationURL"] = md.MlConfirm
	cfm["EnvAuthMailAccountConfirmationRdURL"] = md.MlConfirmRedirect
	cfm["EnvAuthMailAccountRegSubject"] = md.MlRegSubject
	cfm["EnvAuthMailAccountRegPlainTxt"] = md.MlRegTxt
	cfm["EnvAuthMailAccountRegHTML"] = md.MlRegHTML
	cfm["EnvAuthMailCredResetSubject"] = md.MlCredSubject
	cfm["EnvAuthMailCredResetPlainTxt"] = md.MlCredTxt
	cfm["EnvAuthMailCredResetHTML"] = md.MlCredHTML

	return cfm, nil
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
