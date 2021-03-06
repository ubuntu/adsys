// +build tools

package tools

import (
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"

	_ "honnef.co/go/tools/cmd/staticcheck"

	_ "github.com/securego/gosec/cmd/gosec"
)
