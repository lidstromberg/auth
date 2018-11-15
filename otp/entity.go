package otp

//Result holds the data which needs to be persisted for ongoing otp
type Result struct {
	Img    []byte
	Secret string
}
