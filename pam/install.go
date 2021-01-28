// +build tools

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ubuntu/adsys/internal/generators"
)

//go:generate go run install.go install ../generated
func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s [install|clean] DESTDIR", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	mode := os.Args[1]
	destDir := filepath.Join(generators.DestDirectory(os.Args[2]), "lib", os.Getenv("DEB_HOST_GNU_TYPE"), "security")
	switch mode {

	case "install":
		if err := os.MkdirAll(destDir, 0755); err != nil {
			log.Fatal(err)
		}
		args := []string{"--shared", "-Wl,-soname,libpam_adsys.so"}
		for _, flagType := range []string{"CPPFLAGS", "CFLAGS", "LDFLAGS"} {
			for _, f := range strings.Split(os.Getenv(flagType), " ") {
				if strings.TrimSpace(f) == "" {
					continue
				}
				args = append(args, f)
			}
		}

		_, curF, _, ok := runtime.Caller(0)
		if !ok {
			log.Fatal("can't determine current file")
		}
		dir := filepath.Dir(curF)

		args = append(args, "-lpam", "-o", filepath.Join(destDir, "pam_adsys.so"), filepath.Join(dir, "pam_adsys.c"))
		cmd := exec.Command("gcc", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: compilation failed: %v", err)
			os.Exit(1)
		}

	case "clean":
		if err := os.RemoveAll(destDir); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cleaning %s failed: %v", destDir, err)
			os.Exit(1)
		}
	}
}
