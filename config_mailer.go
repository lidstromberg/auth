package auth

import (
	"encoding/json"

	stor "github.com/lidstromberg/storage"
	"golang.org/x/net/context"
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
