//go:build debianvendoring

// This is to get binaries we need when building a package but we don't want to end up in the finale binary.
// In addition, most of them are "package main", which are not really importable.
package adsys

// For package build
import (
	_ "github.com/ubuntu/go-i18n/cmd/compile-mo"
)
