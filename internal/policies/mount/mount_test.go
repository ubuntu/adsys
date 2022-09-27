package mount

import (
	"context"
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

func TestNew(t *testing.T) {
	t.Parallel()

}

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	entries := GetEntries(5, 0, 1, 0, []string{"\n"})

	tests := map[string]struct {
		entries    []entry.Entry
		objectName string
		computer   bool
		uid        string
		gid        string

		wantErr bool
	}{
		"successfully generates mounts file":        {entries: entries},
		"generates no file if there are no entries": {entries: []entry.Entry{}},

		"error when user is not found":    {entries: entries, objectName: "dont exist", wantErr: true},
		"error when user has invalid uid": {entries: entries, uid: "invalid", wantErr: true},
		"error when user has invalid gid": {entries: entries, gid: "invalid", wantErr: true},

		// To be removed when computer policies get implemented.
		"error when trying to apply computer policies": {entries: entries, computer: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mountsPath := filepath.Join(t.TempDir(), t.Name(), "mounts")

			userServicePath := filepath.Join("testdata", "adsys-user-mount.service")

			opts := []Option{WithMountsFilePath(mountsPath), WithUserMountServicePath(userServicePath)}

			usr, _ := user.Current()
			if tc.objectName == "" {
				if tc.uid == "" {
					tc.uid = usr.Uid
				}
				if tc.gid == "" {
					tc.gid = usr.Gid
				}

				tc.objectName = "ubuntu"

				opts = append(opts, WithUserLookup(func(string) (*user.User, error) {
					return &user.User{Uid: tc.uid, Gid: tc.gid}, nil
				}))
			}

			m := New(opts...)

			err := m.ApplyPolicy(context.Background(), tc.objectName, tc.computer, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "Expected an error but got none")
				return
			}
			require.NoError(t, err, "Expected no error but got one")

			b, err := os.ReadFile(mountsPath)
			if len(tc.entries) == 0 {
				require.Error(t, err, "Expected no mounts file")
				return
			}
			require.NoError(t, err, "Expected to read generated mounts file")

			testdata := filepath.Join("testdata", t.Name())
			wantPath := filepath.Join(testdata, "mounts")
			if update {
				err = os.MkdirAll(testdata, 0777)
				require.NoError(t, err, "Expected to create testdata dir for the tests")

				err = os.WriteFile(wantPath, b, 0777)
				require.NoError(t, err, "Expected to update golden file for the test")
			}

			got := string(b)
			b, err = os.ReadFile(wantPath)
			require.NoError(t, err, "Expected to read from golden file")

			require.Equal(t, string(b), got, "Mounts files must match")
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "Update the golden files")
	flag.Parse()
	m.Run()
}
