package log

//go:generate sh -c "PATH=\"$PATH:`go env GOPATH`/bin\" protoc --go_out=. --go_opt=paths=source_relative log.proto"

const (
	logIdentifier = "LOGSTREAMER_MSG"

	clientIDKey         = "ClientID"
	clientWantCallerKey = "ClientWantCallery"
)
