package ad_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad"
)

func TestAdsysGPOList(t *testing.T) {
	prefix := coverageToGoFormat(t, "adsys-gpolist", ad.GoCoverProfile)

	// Setup samba mock
	orig := os.Getenv("PYTHONPATH")
	p, err := filepath.Abs("testdata/adsys-gpolist/mock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for mock")
	require.NoError(t, os.Setenv("PYTHONPATH", p), "Setup: Failed to set $PYTHONPATH")
	t.Cleanup(func() {
		require.NoError(t, os.Setenv("PYTHONPATH", orig), "Teardown: can't restore PYTHONPATH to original value")
	})

	tests := map[string]struct {
		url         string
		accountName string
		objectClass string

		wantErr bool
	}{
		"Return one gpo": {
			accountName: "UserAtRoot",
		},

		"Return hierarchy": {
			accountName: "RnDUser",
		},
		"Multiple GPOs in same OU": {
			accountName: "RnDUserDep1",
		},

		"Machine GPOs": {
			accountName: "hostname1",
			objectClass: "computer",
		},

		"Disabled GPOs": {
			accountName: "RnDUserDep3",
		},

		"No GPO on OU": {
			accountName: "UserNoGPO",
		},

		// Filtering cases
		"Filter user only GPOs": {
			accountName: "hostname2",
			objectClass: "computer",
		},
		"Filter machine only GPOs": {
			accountName: "RnDUserDep7",
		},

		// Forced GPOs and inheritance handling
		"Forced GPO are first by reverse order": {
			accountName: "RndUserSubDep2ForcedPolicy",
		},
		"Block inheritance": {
			accountName: "RnDUserWithBlockedInheritance",
		},
		"Forced GPO and blocked inheritance": {
			accountName: "RnDUserWithBlockedInheritanceAndForcedPolicies",
		},

		// Access cases
		"Security descriptor missing ignores GPO": { // AD is doing that for windows client
			accountName: "RnDUserDep4",
		},
		"Fail on security descriptor access failure": {
			accountName: "RnDUserDep5",
			wantErr:     true,
		},
		"Security descriptor access denied ignores GPO": {
			accountName: "RnDUserDep6",
		},
		"Security descriptor accepted is for another user": {
			accountName: "RnDUserDep8",
		},

		"No gPOptions fallbacks to 0": {
			accountName: "UserNogPOptions",
		},

		// Error cases
		"Fail on unreachable ldap": {
			url:         "ldap://unreachable_url",
			accountName: "bob",
			wantErr:     true,
		},
		"Fail on non existent account": {
			accountName: "nonexistent",
			wantErr:     true,
		},
		"Fail on user requested but found machine": {
			accountName: "hostname1",
			objectClass: "user",
			wantErr:     true,
		},
		"Fail on computer requested but found user": {
			accountName: "UserAtRoot",
			objectClass: "computer",
			wantErr:     true,
		},
		"Fail invalid GPO link": {
			accountName: "UserInvalidLink",
			wantErr:     true,
		},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.objectClass == "" {
				tc.objectClass = "user"
			}
			if tc.url == "" {
				tc.url = "ldap://ldap_url"
			}

			args := append(prefix, "./adsys-gpolist", "--objectclass", tc.objectClass, tc.url, tc.accountName)
			got, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if tc.wantErr {
				require.Error(t, err, "adsys-gpostlist should have failed but didn’t")
				return
			}
			require.NoErrorf(t, err, "adsys-gpostlist should exit successfully: %v", string(got))

			// check collected output between FormatGPO calls
			goldPath := filepath.Join("testdata", "adsys-gpolist", "golden", name)
			// Update golden file
			if ad.Update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, got, 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), string(got), "adsys-gpolist expected output")

		})
	}
}

const coverageCmd = "python3-coverage"

// coverageToGoFormat allow appending for a particular include file to the global go coverage profile
func coverageToGoFormat(t *testing.T, include string, goCoverProfile string) (cmdPrefix []string) {
	t.Helper()

	if goCoverProfile == "" {
		return []string{}
	}

	// Check we have an executable "python3-coverage" in PATH for coverage request
	_, err := exec.LookPath(coverageCmd)
	require.NoErrorf(t, err, "Setup: coverage requested and no %s executable found in $PATH for python code", coverageCmd)

	coverDir := filepath.Dir(goCoverProfile)
	err = os.Setenv("COVERAGE_FILE", filepath.Join(coverDir, "pythoncode.coverage"))
	require.NoError(t, err, "Setup: can’t set python coverage")

	t.Cleanup(func() {
		// Convert to text format
		out, err := exec.Command(coverageCmd, "annotate", "-d", coverDir, "--include", include).CombinedOutput()
		if err != nil {
			t.Fatalf("can’t combine python coverage: %v", string(out))
		}

		// Convert to golang compatible cover format
		// search for go.mod to file fqdnFile
		fqdnFile := fqdnToPath(t, include)

		coverDir := filepath.Dir(goCoverProfile)

		// transform include to golang compatible format
		inF, err := os.Open(filepath.Join(coverDir, include+",cover"))
		if err != nil {
			t.Fatalf("failed opening python cover file: %s", err)
		}
		defer inF.Close()

		golangInclude := filepath.Join(coverDir, include+".gocover")
		outF, err := os.Create(golangInclude)
		if err != nil {
			t.Fatalf("failed opening output golang compatible cover file: %s", err)
		}
		defer outF.Close()

		var line int
		scanner := bufio.NewScanner(inF)
		for scanner.Scan() {
			line++
			txt := scanner.Text()
			if txt == "" {
				continue
			}
			var covered string
			switch txt[0] {
			case '>':
				covered = "1"
			case '!':
				covered = "0"
			default:
				continue
			}

			if _, err := outF.Write([]byte(fmt.Sprintf("%s:%d.1,%d.%d 1 %s\n", fqdnFile, line, line, len(txt), covered))); err != nil {
				t.Fatalf("can't write to golang compatible cover file : %s", err)
			}
		}

		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}

		// append to merge that file when tests are done
		ad.PythonCoveragesToMerge = append(ad.PythonCoveragesToMerge, func() error { return appendToFile(goCoverProfile, golangInclude) })
	})

	return []string{coverageCmd, "run", "-a"}
}

// appendToFile appends toInclude to the coverprofile file at the end
func appendToFile(main, add string) error {
	d, err := os.ReadFile(add)
	if err != nil {
		return fmt.Errorf("can't open python coverage file named: %v", err)
	}

	f, err := os.OpenFile(main, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("can't open golang cover profile file: %v", err)
	}
	if _, err := f.Write(d); err != nil {
		return fmt.Errorf("can't write to golang cover profile file: %v", err)
	}
	return nil
}

// fqdnToPath allows to return the fqdn path for this file relative to go.mod
func fqdnToPath(t *testing.T, path string) string {
	t.Helper()

	srcPath, err := filepath.Abs(path)
	require.NoError(t, err, "can't calculate absolute path")

	d := srcPath
	for d != "/" {
		f, err := os.Open(filepath.Join(d, "go.mod"))
		if err != nil {
			d = filepath.Dir(d)
			continue
		}
		defer f.Close()

		r := bufio.NewReader(f)
		l, err := r.ReadString('\n')
		require.NoError(t, err, "can't read go.mod first line")
		if !strings.HasPrefix(l, "module ") {
			t.Fatal(`failed to find "module" line in go.mod`)
		}

		prefix := strings.TrimSpace(strings.TrimPrefix(l, "module "))
		relpath := strings.TrimPrefix(srcPath, d)
		return filepath.Join(prefix, relpath)
	}

	t.Fatal("failed to find go.mod")
	return ""
}
