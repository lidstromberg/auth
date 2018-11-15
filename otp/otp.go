package otp

import (
	"bytes"
	"image/png"

	"github.com/pquerna/otp/totp"
)

/***************************************************
This OTP uses code from github.com/pquerna/otp

Please refer to this repo if you require otp
functionality. This code is purely for reference
and is derived from the example code from the
github.com/pquerna/otp repo.

***************************************************/

//GenerateOtp is slightly modified example code from github.com/pquerna/otp
func GenerateOtp(issuer, email string, period uint) (*Result, error) {

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		Period:      period,
	})

	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	img, err := key.Image(200, 200)

	if err != nil {
		return nil, err
	}

	png.Encode(&buf, img)

	otp := &Result{
		Img:    buf.Bytes(),
		Secret: key.Secret(),
	}

	return otp, nil
}

//VerifyOtp returns a boolean indicating if the otp is valid for the secret
func VerifyOtp(otp, secret string) bool {

	return totp.Validate(otp, secret)
}
