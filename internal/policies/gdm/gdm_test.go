package gdm_test

import (
	"context"
	"flag"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/gdm"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entries []entry.Entry

		wantErr bool
	}{
		// user cases
		"dconf policy": {entries: []entry.Entry{
			{Key: "dconf/com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}}},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dconfDir := t.TempDir()

			// Apply machine configuration
			dconfManager := dconf.NewWithDconfDir(dconfDir)
			err := dconfManager.ApplyPolicy(context.Background(), "ubuntu", true, nil)
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			m, err := gdm.New(gdm.WithDconf(dconfManager))
			require.NoError(t, err, "Setup: can't create gdm manager")

			err = m.ApplyPolicy(context.Background(), tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, dconfDir, filepath.Join("testdata", "golden", name, "etc", "dconf"), update)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
