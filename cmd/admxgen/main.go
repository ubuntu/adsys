package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/ad/admxgen"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [FLAGS] [COMMAND] [ARGS] ...
Generate ADMX and intermediary working files from a list of policy definition
files

Commands:
  [-root PATH] [-current-session SESSION_NAME] expand SOURCE DEST
	Generates an intermediary policy definition file into DEST directory from
	all the policy definition files in SOURCE directory, using the correct
	decoder.
	The generated definition file will be of the form
	expanded_policies.RELEASE.yaml
	-root is the root filesystem path to use. Default to /.
	-current-session is the current session to consider for dconf per-session
	overrides. Default to "".

  [-auto-detect-releases] [-allow-missing-keys] admx CATEGORIES_DEF.yaml SOURCE DEST
	Collects all intermediary policy definition files in SOURCE directory to
	create admx and adml templates in DEST, based on CATEGORIES_DEF.yaml.
	-auto-detect-releases will override supportedreleases in categories definition
	file and will takes all yaml files in SOURCE directory and use the basename
	as their versions.
	-allow-missing-keys will not fail but display a warning if some keys are not
	available in a release. This is the case when news keys are added to non-lts
	releases.
`, filepath.Base(os.Args[0]))
	}

	flagRoot := flag.String("root", "/", "")
	flagCurrentSession := flag.String("current-session", "", "")

	autoDetectReleases := flag.Bool("auto-detect-releases", false, "")
	allowMissingKeys := flag.Bool("allow-missing-keys", false, "")

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Error("Missing mandatory argument")
		flag.Usage()
		os.Exit(1)
	}
	switch strings.ToLower(args[0]) {
	case "expand":
		if len(args) != 3 {
			log.Error("Command expand is missing mandatory option(s)")
			flag.Usage()
			os.Exit(1)
		}
		if err := admxgen.Expand(args[1], args[2], *flagRoot, *flagCurrentSession); err != nil {
			log.Error(fmt.Errorf("command expand failed with %w", err))
			os.Exit(1)
		}
	case "admx":
		if len(args) != 4 {
			log.Error("Command admx is missing mandatory options(s)")
			flag.Usage()
			os.Exit(1)
		}
		if err := admxgen.Generate(args[1], args[2], args[3], *autoDetectReleases, *allowMissingKeys); err != nil {
			log.Error(fmt.Errorf("command admx failed with %w", err))
			os.Exit(1)
		}
	default:
		log.Errorf("Unknown command: %s", args[0])
		flag.Usage()
		os.Exit(1)
	}
}
