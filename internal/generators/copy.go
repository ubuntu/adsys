//go:build tools
// +build tools

package main

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ubuntu/adsys/internal/generators"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("Expect 3 arguments: <source> <dest> <root_share>")
	}
	dir := filepath.Join(generators.DestDirectory(os.Args[3]), os.Args[2])

	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Couldn't create dest directory: %v", err)
	}
	defer func() {
		// Sleep and force a sync before exiting to avoid possible race
		// conditions during the package build, where the paths to install are
		// not fully written by the time dh_install runs.
		syscall.Sync()
		time.Sleep(1 * time.Second)
	}()

	fromBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Couldn't open source file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, filepath.Base(os.Args[1])), fromBytes, 0666); err != nil {
		log.Fatalf("Couldn't write to dest file: %v", err)
	}
}
