package constants

type ErrorCode string

const (
	ErrorInvalidInput     ErrorCode = "ERROR_INVALID_INPUT"
	ErrorRdapError        ErrorCode = "ERROR_RDAP_ERROR"
	ErrorIp2LocationError ErrorCode = "ERROR_IP2LOCATION_ERROR"
)

type StatusCode string

const (
	StatusOk    StatusCode = "OK"
	StatusError StatusCode = "ERROR"
)
