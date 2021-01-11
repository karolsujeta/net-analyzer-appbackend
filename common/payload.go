package common

type Payload struct {
	Code    int
	Error   string
	Payload interface{}
}

func NewPayloadWrapper(code int, payload interface{}) *Payload {
	payloadWrapper := new(Payload)
	payloadWrapper.Code = code
	payloadWrapper.Payload = payload
	return payloadWrapper
}
