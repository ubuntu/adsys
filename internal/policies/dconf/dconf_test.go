package dconf_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		isComputer       bool
		entries          []entry.Entry
		existingDconfDir string

		wantErr bool
	}{
		// User cases
		"New user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}}},
		"User updates existing value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-user"},
		"User updates with different value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"}},
			existingDconfDir: "existing-user"},
		"User updates key is now disabled": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"}},
			existingDconfDir: "existing-user"},
		"Update user disabled key with value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "user-with-disabled-value"},

		// Machine cases
		"First boot": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "-"},
		"Machine updates existing value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			isComputer: true},
		"Machine updates with different value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"}},
			isComputer: true},
		"Machine updates key is now disabled": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"}},
			isComputer: true},
		"Update machine disabled key with value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "machine-with-disabled-value"},

		// We still need to create an empty database even if there is no policy, otherwise DCONF will block any writes
		// due to missing database profile stack file.
		"No policy still generates a valid db": {entries: nil},

		"Multiple keys same category": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
		}},
		"Multiple sections": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Value: "'onekey-s2'", Meta: "s"},
		}},
		"Multiple sections with disabled keys": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Disabled: true, Meta: "s"},
		}},
		"Mixing sections and keys still groups sections": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Value: "'onekey-s2'", Meta: "s"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
		}},

		// Update edge cases
		"No update when no change": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "existing-user"},
		"Missing machine compiled db for machine": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "missing-machine-compiled-db"},
		"Missing machine compiled db for user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: false, existingDconfDir: "missing-machine-compiled-db"},
		"Missing user compiled db for user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "missing-user-compiled-db"},

		// Normalized keys formats
		"Normalized canonical form for each supported key": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s'", Meta: "s"},
			{Key: "com/ubuntu/category/key-i", Value: "'42'", Meta: "i"},
			{Key: "com/ubuntu/category/key-b", Value: "true", Meta: "b"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
			{Key: "com/ubuntu/category/key-ai", Value: "[42]", Meta: "ai"},
			{Key: "com/ubuntu/category/key-returnedunmodified", Value: "[[1,2,3],[4,5,6]]", Meta: "aai"},
		}},

		// help users with quoting, normalizing… (common use cases here: more tests in internal_tests)
		"Unquoted string": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "onekey-s", Meta: "s"},
		}},
		"Quoted i": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-i", Value: "'1'", Meta: "i"},
		}},
		"Quoted b": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-b", Value: "'true'", Meta: "b"},
		}},
		"No surrounding brackets ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1", Meta: "ai"},
		}},
		"No surrounding brackets multiple ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1,2", Meta: "ai"},
		}},
		"No surrounding brackets unquoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "simple-as", Meta: "as"},
		}},
		"No surrounding brackets unquoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "two-as1, two-as2", Meta: "as"},
		}},
		"No surrounding brackets quoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "'simple-as'", Meta: "as"},
		}},
		"No surrounding brackets quoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "'two-as1', 'two-as2'", Meta: "as"},
		}},
		"Multi-lines as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "first\nsecond\n", Meta: "as"},
		}},
		"Multi-lines as mixed with comma": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "first,second\nthird\n", Meta: "as"},
		}},
		"Multi-lines ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1\n2\n", Meta: "ai"},
		}},
		"Multi-lines ai mixed with comma": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1,2\n3\n", Meta: "ai"},
		}},

		// Profiles tests
		"Update existing correct profile stays unchanged": {entries: nil,
			existingDconfDir: "existing-user"},
		"Update existing correct profile with trailing spaces are removed": {entries: nil,
			existingDconfDir: "existing-user-with-trailing-spaces"},
		"Update existing profile without needed db append them": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb"},
		"Update existing profile without needed db, trailine lines are removed": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb-trailing-newlines"},
		"Update existing profile with partial db append them without repetition": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-partial"},
		"Update existing profile with wrong order appends them in correct order": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-reversed-end"},
		"Update existing profile eliminates adsys DB repetitions": {entries: nil,
			existingDconfDir: "existing-user-adsysdb-repetitions"},

		// non adsys content
		"Do not update other files from db": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-user-with-extra-files"},
		"Do not interfere with other user profile": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-other-user"},

		"Invalid as is too robust to produce defaulting values": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: `[value1, ] value2]`, Meta: "as"},
		}},

		// Error cases
		"Error when machine db does not exist": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
		}, existingDconfDir: "-", wantErr: true},
		"Error on invalid ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "[1,b]", Meta: "ai"},
		}, wantErr: true},
		"Error on invalid value for unnormalized type": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-i", Value: "NaN", Meta: "i"},
		}, wantErr: true},
		"Error on invalid type": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-something", Value: "value", Meta: "sometype"},
		}, wantErr: true},
		"Error on empty meta": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-something", Value: "value", Meta: ""},
		}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dconfDir := t.TempDir()

			if tc.existingDconfDir == "" {
				tc.existingDconfDir = "machine-base"
			}
			if tc.existingDconfDir != "-" {
				require.NoError(t, os.Remove(dconfDir), "Setup: can't delete dconf base directory before recreation")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join(testutils.TestFamilyPath(t), "dconf", tc.existingDconfDir), dconfDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial dconf directory")
			}

			m := dconf.NewWithDconfDirAndProfileDataDirs(dconfDir, []string{})
			err := m.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, dconfDir, testutils.GoldenPath(t), testutils.UpdateEnabled())
		})
	}
}

// seedHeaderPlaceholder stands, in the test table, for a header that records
// the system profile adsys seeds from. It is formatted with the index of that
// profile, and resolved once the test knows its path.
const (
	seedHeaderPlaceholder = "<seeded-from-%d>"
	fallbackSeedHeader    = "# Generated by adsys and refreshed with the policy.\n" +
		"# Remove this header to manage this profile yourself."
)

func seedHeader(dataDir string) string {
	return "# Generated by adsys from " + filepath.Join(dataDir, "dconf", "profile", "gdm") +
		", and refreshed with the policy.\n# Remove this header to manage this profile yourself."
}

func TestApplyPolicyPreservesSystemProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		localProfile   string
		systemProfiles []string
		wantProfile    string
	}{
		{
			name: "No system profile uses the default",
			wantProfile: strings.Join([]string{
				fallbackSeedHeader,
				"user-db:user",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "System profile preserves the greeter file database",
			systemProfiles: []string{
				"",
				"user-db:user\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 1),
				"user-db:user",
				"file-db:/usr/share/gdm/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "First system profile in search order wins",
			systemProfiles: []string{
				"user-db:user\nfile-db:/usr/local/share/gdm-defaults\n",
				"user-db:user\nfile-db:/usr/share/gdm-defaults\n",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"file-db:/usr/local/share/gdm-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "Creates a local profile when fallback already contains ADSys databases",
			systemProfiles: []string{
				"user-db:user\nsystem-db:gdm\nsystem-db:machine",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "Blank system profile uses the default",
			systemProfiles: []string{
				"\n \n",
			},
			wantProfile: strings.Join([]string{
				fallbackSeedHeader,
				"user-db:user",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name:         "Existing local profile takes precedence",
			localProfile: "user-db:user\nfile-db:/etc/gdm/greeter-dconf-defaults\n",
			systemProfiles: []string{
				"user-db:user\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				"user-db:user",
				"file-db:/etc/gdm/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name:         "Profile generated by a previous release is reseeded",
			localProfile: "user-db:user\nsystem-db:gdm\nsystem-db:machine",
			systemProfiles: []string{
				"user-db:user\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"file-db:/usr/share/gdm/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name:         "Profile generated by a previous release is kept without a system profile",
			localProfile: "user-db:user\nsystem-db:gdm\nsystem-db:machine",
			wantProfile: strings.Join([]string{
				fallbackSeedHeader,
				"user-db:user",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name:         "Blank local profile is reseeded",
			localProfile: "\n \n",
			systemProfiles: []string{
				"user-db:user\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"file-db:/usr/share/gdm/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "Profile carrying our header is reseeded from the system profile",
			localProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"file-db:/var/lib/gdm3/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
			systemProfiles: []string{
				"user-db:user\nfile-db:/var/lib/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				fmt.Sprintf(seedHeaderPlaceholder, 0),
				"user-db:user",
				"file-db:/var/lib/gdm/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
		{
			name: "Profile whose header was removed is left to the administrator",
			localProfile: strings.Join([]string{
				"user-db:user",
				"file-db:/var/lib/gdm3/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
			systemProfiles: []string{
				"user-db:user\nfile-db:/var/lib/gdm/greeter-dconf-defaults\n",
			},
			wantProfile: strings.Join([]string{
				"user-db:user",
				"file-db:/var/lib/gdm3/greeter-dconf-defaults",
				"system-db:gdm",
				"system-db:machine",
			}, "\n"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dconfDir := t.TempDir()
			machineLocksDir := filepath.Join(dconfDir, "db", "machine.d", "locks")
			require.NoError(t, os.MkdirAll(machineLocksDir, 0750))
			require.NoError(t, os.WriteFile(filepath.Join(machineLocksDir, "adsys"), nil, 0600))

			dataDirs := make([]string, 0, len(tc.systemProfiles))
			for _, systemProfile := range tc.systemProfiles {
				dataDir := t.TempDir()
				dataDirs = append(dataDirs, dataDir)
				if systemProfile == "" {
					continue
				}

				systemProfilePath := filepath.Join(dataDir, "dconf", "profile", "gdm")
				require.NoError(t, os.MkdirAll(filepath.Dir(systemProfilePath), 0750))
				require.NoError(t, os.WriteFile(systemProfilePath, []byte(systemProfile), 0600))
			}

			resolve := func(s string) string {
				for i, dataDir := range dataDirs {
					s = strings.ReplaceAll(s, fmt.Sprintf(seedHeaderPlaceholder, i), seedHeader(dataDir))
				}
				return s
			}
			wantProfile := resolve(tc.wantProfile)

			if tc.localProfile != "" {
				localProfilePath := filepath.Join(dconfDir, "profile", "gdm")
				require.NoError(t, os.MkdirAll(filepath.Dir(localProfilePath), 0750))
				require.NoError(t, os.WriteFile(localProfilePath, []byte(resolve(tc.localProfile)), 0600))
			}

			m := dconf.NewWithDconfDirAndProfileDataDirs(dconfDir, dataDirs)
			require.NoError(t, m.ApplyPolicy(context.Background(), "gdm", false, nil))

			profilePath := filepath.Join(dconfDir, "profile", "gdm")
			profile, err := os.ReadFile(profilePath)
			require.NoError(t, err)
			require.Equal(t, wantProfile, string(profile))

			// Applying the policy again must be a no-op: the profile we just
			// generated is our own and must not be reseeded over and over.
			require.NoError(t, m.ApplyPolicy(context.Background(), "gdm", false, nil))
			profile, err = os.ReadFile(profilePath)
			require.NoError(t, err)
			require.Equal(t, wantProfile, string(profile), "Reapplying the policy changed the profile")
		})
	}
}

func TestApplyPolicyFollowsSystemProfileChanges(t *testing.T) {
	t.Parallel()

	dconfDir := t.TempDir()
	machineLocksDir := filepath.Join(dconfDir, "db", "machine.d", "locks")
	require.NoError(t, os.MkdirAll(machineLocksDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(machineLocksDir, "adsys"), nil, 0600))

	dataDir := t.TempDir()
	systemProfilePath := filepath.Join(dataDir, "dconf", "profile", "gdm")
	require.NoError(t, os.MkdirAll(filepath.Dir(systemProfilePath), 0750))

	m := dconf.NewWithDconfDirAndProfileDataDirs(dconfDir, []string{dataDir})
	applyAndRead := func() string {
		require.NoError(t, m.ApplyPolicy(context.Background(), "gdm", false, nil))
		profile, err := os.ReadFile(filepath.Join(dconfDir, "profile", "gdm"))
		require.NoError(t, err)
		return string(profile)
	}

	require.NoError(t, os.WriteFile(systemProfilePath, []byte("user-db:user\nfile-db:/var/lib/gdm3/greeter-dconf-defaults\n"), 0600))
	require.Equal(t, strings.Join([]string{
		seedHeader(dataDir),
		"user-db:user",
		"file-db:/var/lib/gdm3/greeter-dconf-defaults",
		"system-db:gdm",
		"system-db:machine",
	}, "\n"), applyAndRead())

	// The package owning the system profile moves its defaults elsewhere: our
	// copy must follow instead of shadowing it with a path that is now gone.
	require.NoError(t, os.WriteFile(systemProfilePath, []byte("user-db:user\nfile-db:/var/lib/gdm/greeter-dconf-defaults\n"), 0600))
	require.Equal(t, strings.Join([]string{
		seedHeader(dataDir),
		"user-db:user",
		"file-db:/var/lib/gdm/greeter-dconf-defaults",
		"system-db:gdm",
		"system-db:machine",
	}, "\n"), applyAndRead())

	// And when the system profile goes away, so do the sources we borrowed.
	require.NoError(t, os.Remove(systemProfilePath))
	require.Equal(t, strings.Join([]string{
		fallbackSeedHeader,
		"user-db:user",
		"system-db:gdm",
		"system-db:machine",
	}, "\n"), applyAndRead())
}

func TestApplyPolicyRejectsObjectNameDesignatingAPath(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"Parent directory":   "..",
		"Current directory":  ".",
		"Relative path":      "dir/gdm",
		"Traversal":          "../../../../etc/shadow",
		"Absolute path":      "/etc/shadow",
		"Empty name":         "",
		"Trailing separator": "gdm/",
	}

	for name, objectName := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dconfDir := t.TempDir()
			machineLocksDir := filepath.Join(dconfDir, "db", "machine.d", "locks")
			require.NoError(t, os.MkdirAll(machineLocksDir, 0750))
			require.NoError(t, os.WriteFile(filepath.Join(machineLocksDir, "adsys"), nil, 0600))

			m := dconf.NewWithDconfDirAndProfileDataDirs(dconfDir, []string{})
			require.Error(t, m.ApplyPolicy(context.Background(), objectName, false, nil),
				"ApplyPolicy should refuse an object name designating a path")
		})
	}
}
