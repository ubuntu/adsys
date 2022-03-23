package policies_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestNew(t *testing.T) {
	t.Parallel()

	gpos := []policies.GPO{
		{ID: "{GPOId}", Name: "GPOName", Rules: map[string][]entry.Entry{
			"dconf": {
				entry.Entry{Key: "path/to/key1", Value: "ValueOfKey1", Meta: "s"},
				entry.Entry{Key: "path/to/key2", Value: "ValueOfKey2\nOn\nMultilines\n", Meta: "s"},
			},
			"scripts": {
				entry.Entry{Key: "path/to/key3", Disabled: true},
			},
		}},
	}

	tests := map[string]struct {
		gpos     []policies.GPO
		assetsDB string

		wantErr bool
	}{
		"gpos only": {
			gpos: gpos,
		},
		"with assets": {
			gpos:     gpos,
			assetsDB: "testdata/cache/policies/with_assets/assets.db",
		},
		"no gpos": {
			gpos: nil,
		},

		// error cases
		"error on invalid assets db": {
			assetsDB: "testdata/cache/policies/invalid_assets_db/assets.db",
			wantErr:  true,
		},
		"error on assets db does not exists": {
			assetsDB: "testdata/cache/policies/doesnotexists/assets.db",
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := policies.New(context.Background(), tc.gpos, tc.assetsDB)
			if tc.wantErr {
				require.Error(t, err, "New should return an error but got none")
				return
			}
			require.NoError(t, err, "New should return no error but got one")
			defer got.Close()

			equalPoliciesToGolden(t, got, filepath.Join("testdata", "golden", "new", name), update)
		})
	}
}

func TestNewFromCache(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cacheDir string

		wantErr bool
	}{
		"gpos only": {
			cacheDir: "simple",
		},
		"with assets": {
			cacheDir: "with_assets",
		},

		// error cases
		"error on invalid policies cache": {
			cacheDir: "invalid_policies_cache",
			wantErr:  true,
		},
		"error on invalid assets db": {
			cacheDir: "invalid_assets_db",
			wantErr:  true,
		},
		"error on no policies cache": {
			cacheDir: "doesnotexists",
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := policies.NewFromCache(context.Background(), filepath.Join("testdata", "cache", "policies", tc.cacheDir))
			if tc.wantErr {
				require.Error(t, err, "NewFromCache should return an error but got none")
				return
			}
			require.NoError(t, err, "NewFromCache should return no error but got one")
			defer got.Close()

			equalPoliciesToGolden(t, got, filepath.Join("testdata", "golden", "newfromcache", name), update)
		})
	}
}

func TestSave(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cacheSrc string

		transformDest     string
		initialCacheDir   string
		saveTwiceSameDest bool

		wantErr bool
	}{
		"gpos only": {
			cacheSrc: "simple",
		},
		"with assets": {
			cacheSrc: "with_assets",
		},

		// refresh existing directory
		"existing policies cache is refreshed": {
			cacheSrc:        "one_gpo",
			initialCacheDir: "one_gpo_other",
		},
		"existing assets cache is refreshed": {
			cacheSrc:        "with_assets",
			initialCacheDir: "with_assets_other",
		},
		"existing cache with assets, new cache with no assets": {
			cacheSrc:        "one_gpo",
			initialCacheDir: "with_assets",
		},
		"save assets on existing opened file does not segfault": {
			cacheSrc:          "with_assets",
			initialCacheDir:   "with_assets",
			saveTwiceSameDest: true,
		},

		// edge cases
		"destdir does not exists": {
			cacheSrc:      "one_gpo",
			transformDest: "destdir does not exists",
		},
		"can refresh on existing read only asset file": {
			cacheSrc:        "with_assets",
			initialCacheDir: "with_assets_other",
			transformDest:   "read only asset file",
		},

		// error cases
		"error on can’t write to policies base dir": {
			cacheSrc:      "with_assets",
			transformDest: "read only policies base directory",
			wantErr:       true,
		},
		"error on can’t write to dest dir": {
			cacheSrc:      "with_assets",
			transformDest: "read only destination directory",
			wantErr:       true,
		},
		"error on can’t remove existing assets": {
			cacheSrc:        "one_gpo",
			initialCacheDir: "with_assets_other",
			transformDest:   "unremovable asset",
			wantErr:         true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join("testdata", "cache", "policies", tc.cacheSrc)
			dest := t.TempDir()

			if tc.initialCacheDir != "" {
				require.NoError(t, os.RemoveAll(dest), "Setup: can’t remove destination directory before copy")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "cache", "policies", tc.initialCacheDir),
						dest,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial cache directory")
			}

			pols, err := policies.NewFromCache(context.Background(), src)
			require.NoError(t, err, "Setup: NewFromCache should return no error but got one")
			defer pols.Close()

			switch tc.transformDest {
			case "destdir does not exists":
				require.NoError(t, os.RemoveAll(dest), "Setup: can’t remove destination directory")
			case "read only policies base directory":
				// make dest a subdirectory and mark RO parent one
				dest = filepath.Join(dest, "dest")
				testutils.MakeReadOnly(t, filepath.Dir(dest))
			case "read only destination directory":
				testutils.MakeReadOnly(t, dest)
			case "read only asset file":
				testutils.MakeReadOnly(t, filepath.Join(dest, policies.PoliciesAssetsFileName))
			case "unremovable asset":
				// To mock unremovable asset file (making it read only is not enough), create instead a non empty
				// directory. If we make the parent directory read only, then policies save will first fail.
				p := filepath.Join(dest, policies.PoliciesAssetsFileName)
				require.NoError(t, os.RemoveAll(p), "Setup: can’t remove assets file")
				// This is any random non empty directory
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "cache", "policies", tc.initialCacheDir),
						p,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't mock unremovable assets file")
			}

			err = pols.Save(dest)
			if tc.wantErr {
				require.Error(t, err, "Save should return an error but got none")
				return
			}
			require.NoError(t, err, "Save should return no error but got one")

			testutils.CompareTreesWithFiltering(t, dest, filepath.Join("testdata", "golden", "save", name), update)
			// compare that assets compressed db corresponds to source.
			testutils.CompareTreesWithFiltering(t, filepath.Join(dest, policies.PoliciesAssetsFileName), filepath.Join(src, policies.PoliciesAssetsFileName), false)

			if !tc.saveTwiceSameDest {
				return
			}
			// SIGBUS is not a panic, so we can’t catch it.
			// See https://github.com/golang/go/issues/41155
			err = pols.Save(dest)
			require.NoError(t, err, "Save should allow re-saving on existing file")
		})
	}
}

func TestCachePolicies(t *testing.T) {
	t.Parallel()

	pols := policies.Policies{
		GPOs: []policies.GPO{
			{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "C", Value: "oneValueC"},
				}}},
			{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA", Meta: "My meta"},
					{Key: "B", Value: "standardB", Disabled: true},
					// this value will be overridden with the higher one
					{Key: "C", Value: "standardC"},
				}}},
		},
	}

	p := filepath.Join(t.TempDir(), "policies-cache")
	err := pols.Save(p)
	require.NoError(t, err, "Save policies without error")

	got, err := policies.NewFromCache(context.Background(), p)
	require.NoError(t, err, "Got policies without error")
	defer got.Close()

	require.Equal(t, pols, got, "Reloaded policies after caching should be the same")

	err = pols.Save(p)
	require.NoError(t, err, "Second save on policies without error")
}

func TestSaveAssetsTo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		relSrc string
		uid    int // we will default it to -1 if no set
		gid    int // we will default it to -1 if no set

		cacheSrc     string
		readOnlyDest string
		destExists   bool

		wantErr bool
	}{
		"all": {
			relSrc:   ".",
			cacheSrc: "with_assets",
		},
		"sub directory": {
			relSrc:   "scripts",
			cacheSrc: "with_assets",
		},
		"sub directory ending with slash": {
			relSrc:   "scripts/",
			cacheSrc: "with_assets",
		},
		"file": {
			relSrc:   "scripts/script-simple.sh",
			cacheSrc: "with_assets",
		},

		"chown directories and files when requested": {
			relSrc:   ".",
			uid:      os.Getuid(),
			gid:      os.Getgid(),
			cacheSrc: "with_assets",
		},

		// error cases
		"error on unexisting relSrc in cache": {
			relSrc:   "doesnotexists",
			cacheSrc: "with_assets",
			wantErr:  true,
		},
		"error on empty relSrc": {
			relSrc:   "",
			cacheSrc: "with_assets",
			wantErr:  true,
		},
		"error on no assets": {
			cacheSrc: "one_gpo",
			wantErr:  true,
		},
		"error on read only dest": {
			relSrc:       ".",
			cacheSrc:     "with_assets",
			readOnlyDest: ".",
			wantErr:      true,
		},
		"error on file read only existing in dest": {
			relSrc:       ".",
			cacheSrc:     "with_assets",
			readOnlyDest: "scripts/script-simple.sh",
			wantErr:      true,
		},
		"error on dest already exists": {
			relSrc:     ".",
			cacheSrc:   "with_assets",
			destExists: true,
			wantErr:    true,
		},
		"error on can't chown to user": {
			relSrc:   ".",
			uid:      -2,
			gid:      -2,
			cacheSrc: "with_assets",
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join("testdata", "cache", "policies", tc.cacheSrc)
			dest := t.TempDir()

			if tc.readOnlyDest != "" {
				if tc.readOnlyDest != "." {
					// we simulate unwritable dest by making the targeted file a directory
					err := os.MkdirAll(filepath.Join(dest, tc.readOnlyDest), 0700)
					require.NoError(t, err, "Setup: can’t mock readOnlyDest file")
				}
				testutils.MakeReadOnly(t, filepath.Join(dest, tc.readOnlyDest))
			} else if !tc.destExists {
				// we simulate unexisting dest by removing it
				require.NoError(t, os.RemoveAll(dest), "Setup: can't mock unexisting dest")
			}

			if tc.uid == 0 {
				tc.uid = -1
			}
			if tc.gid == 0 {
				tc.gid = -1
			}

			pols, err := policies.NewFromCache(context.Background(), src)
			require.NoError(t, err, "Setup: NewFromCache should return no error but got one")
			defer pols.Close()

			err = pols.SaveAssetsTo(context.Background(), tc.relSrc, dest, tc.uid, tc.gid)
			if tc.wantErr {
				require.Error(t, err, "SaveAssetsTo should return an error but got none")
				return
			}
			require.NoError(t, err, "SaveAssetsTo should return no error but got one")

			testutils.CompareTreesWithFiltering(t, dest, filepath.Join("testdata", "golden", "saveassetsto", name), update)
		})
	}
}

func TestCompressAssets(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		src string

		readOnly string

		wantErr bool
	}{
		"no db": {
			src: "assets no db",
		},
		"existing db": {
			src: "assets with db",
		},

		// error cases
		/*
			This fails on RemoveAll(), so same than the case below
			"error on can’t create new db": {
				src:      "assets no db",
				readOnly: ".",
				wantErr:  true,
			},*/
		"error on can’t remove existing db": {
			src:      "assets with db",
			readOnly: ".",
			wantErr:  true,
		},
		"error on non existing directory": {
			src:     "",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := t.TempDir()
			require.NoError(t, os.RemoveAll(p), "Setup: can’t remove destination directory before copy")

			// Copy src to a temporary dir as we will create the db in the same dir
			assetsDir := filepath.Join(p, "assets")
			if tc.src != "" {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "cache", "sysvol", tc.src),
						p,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can’t copy assets directory")

				// We need a fixed modification and creation time on our assets to have reproducible test
				// on zip modification time stored for content.
				fixedTime := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
				err := filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
					return os.Chtimes(path, fixedTime, fixedTime)
				})
				require.NoError(t, err, "Setup: can’t set fixed time for assets")
			}

			// Make some files/dirs read only
			if tc.readOnly != "" {
				// check if readOnly already exists, otherwise create a file
				dest := filepath.Join(p, tc.readOnly)
				if _, err := os.Stat(dest); errors.Is(err, fs.ErrNotExist) {
					err := os.WriteFile(dest, []byte(""), 0400)
					require.NoError(t, err, "Setup: can’t create readOnly file")
				}
				testutils.MakeReadOnly(t, dest)
			}

			err := policies.CompressAssets(context.Background(), assetsDir)
			if tc.wantErr {
				require.Error(t, err, "CompressAssets should return an error but got none")
				return
			}
			require.NoError(t, err, "CompressAssets should return no error but got one")

			// Remove uncompressed assets dir for golden
			require.NoError(t, os.RemoveAll(assetsDir), "Teardown: can’t remove assets directory")

			// Unfortunately, compression seems to be machine dependent, so we can’t compare the zip
			// Also, we need an empty "policies" file for NewFromCache
			err = os.WriteFile(filepath.Join(p, policies.PoliciesFileName), nil, 0600)
			require.NoError(t, err, "Teardown: Can’t create empty policy cache file")

			got, err := policies.NewFromCache(context.Background(), p)
			require.NoError(t, err, "Teardown: NewFromCache should return no error but got one")
			defer got.Close()

			equalPoliciesToGolden(t, got, filepath.Join("testdata", "golden", "compressassets", name), update)
		})
	}
}

func TestGetUniqueRules(t *testing.T) {
	t.Parallel()

	standardGPO := policies.GPO{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

	tests := map[string]struct {
		gpos []policies.GPO

		want map[string][]entry.Entry
	}{
		"One GPO": {
			gpos: []policies.GPO{standardGPO},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Order key ascii": {
			gpos: []policies.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "Z", Value: "standardZ"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
					{Key: "Z", Value: "standardZ"},
				},
			}},

		// Multiple domains cases
		"Multiple domains, same GPOs": {
			gpos: []policies.GPO{
				{ID: "gpomultidomain", Name: "gpomultidomain-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						{Key: "C", Value: "standardC"},
					},
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Multiple domains, different GPOs": {
			gpos: []policies.GPO{standardGPO,
				{ID: "gpo2", Name: "gpo2-name", Rules: map[string][]entry.Entry{
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Same key in different domains are kept separated": {
			gpos: []policies.GPO{
				{ID: "gpoDomain1", Name: "gpoDomain1-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "Common", Value: "commonValueDconf"},
					},
					"otherdomain": {
						{Key: "Common", Value: "commonValueOtherDomain"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "Common", Value: "commonValueDconf"},
				},
				"otherdomain": {
					{Key: "Common", Value: "commonValueOtherDomain"},
				},
			}},

		// Override cases
		// This is ordered for each type by key ascii order
		"Two policies, with overrides": {
			gpos: []policies.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						// this value will be overridden with the higher one
						{Key: "C", Value: "standardC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, with reversed overrides": {
			gpos: []policies.GPO{
				standardGPO,
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						// this value will be overridden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Two policies, no overrides": {
			gpos: []policies.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, no overrides, reversed": {
			gpos: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		"Disabled value overrides non disabled one": {
			gpos: []policies.GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardGPO,
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Disabled: true},
				},
			}},
		"Disabled value is overridden": {
			gpos: []policies.GPO{
				standardGPO,
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},

		"More policies, with multiple overrides": {
			gpos: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				standardGPO,
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		// append/prepend cases
		"Append policy entry, one GPO": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, one GPO, disabled key is ignored": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": nil,
			}},
		"Append policy entry, multiple GPOs": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, first": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, second": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, closest meta wins": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Meta: "furthest meta", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
				},
			}},

		// Mix append and override: closest win
		"Mix meta on GPOs, furthest policy entry is append, closest is override": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value"},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value"},
				},
			}},
		"Mix meta on GPOs, closest policy entry is append, furthest override is ignored": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value"},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pols := policies.Policies{
				GPOs: tc.gpos,
			}
			got := pols.GetUniqueRules()
			require.Equal(t, tc.want, got, "GetUniqueRules returns expected policy entries with correct overrides")
		})
	}
}

// equalPoliciesToGolden compares the policies to the given file.
func equalPoliciesToGolden(t *testing.T, got policies.Policies, golden string, update bool) {
	t.Helper()

	// Save policies and deserialize assets to compare them with golden.
	compareDir := t.TempDir()
	err := got.Save(compareDir)
	require.NoError(t, err, "Teardown: saving gpo should work")
	if got.HasAssets() {
		err = got.SaveAssetsTo(context.Background(), ".", filepath.Join(compareDir, "assets.db.uncompressed"), -1, -1)
		require.NoError(t, err, "Teardown: deserializing assets should work")
		// Remove database that are different from machine to machine.
		err = os.RemoveAll(filepath.Join(compareDir, "assets.db"))
		require.NoError(t, err, "Teardown: cleaning up assets db file")
	}

	testutils.CompareTreesWithFiltering(t, compareDir, golden, update)
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	// Don’t setup samba or sssd for mock helpers
	if !strings.Contains(strings.Join(os.Args, " "), "TestMock") {
		// Ubuntu Advantage
		defer testutils.StartLocalSystemBus()()

		conn, err := dbus.SystemBusPrivate()
		if err != nil {
			log.Fatalf("Setup: can’t get a private system bus: %v", err)
		}
		defer func() {
			if err = conn.Close(); err != nil {
				log.Fatalf("Teardown: can’t close system dbus connection: %v", err)
			}
		}()
		if err = conn.Auth(nil); err != nil {
			log.Fatalf("Setup: can’t auth on private system bus: %v", err)
		}
		if err = conn.Hello(); err != nil {
			log.Fatalf("Setup: can’t send hello message on private system bus: %v", err)
		}

		intro := fmt.Sprintf(`
		<node>
			<interface name="%s">
				<property name='Attached' type='b' access="readwrite"/>
			</interface>%s%s</node>`, consts.SubscriptionDbusInterface, introspect.IntrospectDataString, prop.IntrospectDataString)
		ua := struct{}{}
		if err := conn.Export(ua, consts.SubscriptionDbusObjectPath, consts.SubscriptionDbusInterface); err != nil {
			log.Fatalf("Setup: could not export subscription object: %v", err)
		}

		propsSpec := map[string]map[string]*prop.Prop{
			consts.SubscriptionDbusInterface: {
				"Attached": {
					Value:    true,
					Writable: true,
					Emit:     prop.EmitTrue,
					Callback: func(c *prop.Change) *dbus.Error { return nil },
				},
			},
		}
		_, err = prop.Export(conn, consts.SubscriptionDbusObjectPath, propsSpec)
		if err != nil {
			log.Fatalf("Setup: could not export property for subscription object: %v", err)
		}

		if err := conn.Export(introspect.Introspectable(intro), consts.SubscriptionDbusObjectPath,
			"org.freedesktop.DBus.Introspectable"); err != nil {
			log.Fatalf("Setup: could not export introspectable subscription object: %v", err)
		}

		reply, err := conn.RequestName(consts.SubscriptionDbusRegisteredName, dbus.NameFlagDoNotQueue)
		if err != nil {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
		}
	}

	m.Run()
}
