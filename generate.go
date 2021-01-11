package adsys

//go:generate sh -c "if go run internal/generators/can_modify_repo.go 2>/dev/null; then PATH=\"$PATH:`go env GOPATH`/bin\" protoc --proto_path=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative adsys.proto; fi"
