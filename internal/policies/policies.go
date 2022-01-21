package policies

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"golang.org/x/exp/mmap"
	"gopkg.in/yaml.v3"
)

const (
	// PoliciesCacheBaseName is the base directory where we want to cache policies.
	PoliciesCacheBaseName  = "policies"
	policiesFileName       = "policies"
	policiesAssetsFileName = "assets.db"
)

type assetsFromMMAP struct {
	*zip.Reader
	filemmap *mmap.ReaderAt
}

// Policies is the list of GPOs applied to a particular object, with the global data cache.
type Policies struct {
	GPOs   []GPO
	assets *assetsFromMMAP `yaml:"-"`
}

// New returns new policies with GPOs and assets loaded from DB.
// We pass directly the compressed DB and don’t save immediately in cache as we will do it
// once the gpos are all treated.
func New(ctx context.Context, gpos []GPO, assetsDBPath string) (pols Policies, err error) {
	defer decorate.OnError(&err, i18n.G("can't created new policies"))

	log.Debugf(ctx, "Creating new policies")

	// assets are optionals
	var assets *assetsFromMMAP
	if assetsDBPath != "" {
		if assets, err = openAssetsInMemory(assetsDBPath); err != nil {
			return pols, err
		}
	}

	return Policies{
		GPOs:   gpos,
		assets: assets,
	}, nil
}

// NewFromCache returns cached policies loaded from the p cache directory.
func NewFromCache(ctx context.Context, p string) (pols Policies, err error) {
	defer decorate.OnError(&err, i18n.G("can't get cached policies from %s"), p)

	log.Debugf(ctx, "Loading policies from cache using %s", p)

	d, err := os.ReadFile(filepath.Join(p, policiesFileName))
	if err != nil {
		return pols, err
	}

	if err := yaml.Unmarshal(d, &pols); err != nil {
		return pols, err
	}

	// assets are optionals
	if _, err := os.Stat(filepath.Join(p, policiesAssetsFileName)); err != nil && os.IsNotExist(err) {
		return pols, nil
	}

	// Now, load data from cache.
	assets, err := openAssetsInMemory(filepath.Join(p, policiesAssetsFileName))
	if err != nil {
		return pols, err
	}
	pols.assets = assets

	return pols, nil
}

// openAssetsInMemory opens assetsDB into memory.
// It’s up to the caller to close the opened file.
func openAssetsInMemory(assetsDB string) (assets *assetsFromMMAP, err error) {
	defer decorate.OnError(&err, "can't open assets in memory")

	f, err := mmap.Open(assetsDB)
	if err != nil {
		return nil, err
	}

	r, err := zip.NewReader(f, int64(f.Len()))
	if err != nil {
		return nil, fmt.Errorf(i18n.G("invalid zip db archive: %w"), err)
	}

	return &assetsFromMMAP{
		Reader:   r,
		filemmap: f,
	}, nil
}

// Save serializes in p policies.
// It saves the assets also if not loaded from cache and switch to it.
func (pols *Policies) Save(p string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't save policies to %s"), p)

	if err := os.MkdirAll(p, 0700); err != nil {
		return err
	}

	// GPOs policies
	d, err := yaml.Marshal(pols)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p, policiesFileName), d, 0600); err != nil {
		return err
	}

	assetPath := filepath.Join(p, policiesAssetsFileName)
	if pols.assets == nil {
		// delete assetPath and ignore if it doesn't exist
		if err := os.Remove(assetPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	// Save assets to user cache and reload it
	dr := &readerAtToReader{ReaderAt: pols.assets.filemmap}
	f, err := os.Create(assetPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = io.Copy(f, dr); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Close previous mmaped file
	if err := pols.Close(); err != nil {
		return err
	}

	// redirect from cache
	pols.assets, err = openAssetsInMemory(assetPath)
	if err != nil {
		return err
	}

	return nil
}

// Close closes underlying mmaped file.
func (pols *Policies) Close() (err error) {
	if pols.assets == nil {
		return nil
	}
	if err := pols.assets.filemmap.Close(); err != nil {
		return err
	}
	pols.assets = nil
	return nil
}

type readerAtToReader struct {
	io.ReaderAt
	pos int64
}

func (r *readerAtToReader) Read(p []byte) (n int, err error) {
	n, err = r.ReadAt(p, r.pos)
	if err != nil {
		return n, err
	}
	r.pos += int64(n)

	return n, err
}

// SaveAssetsTo creates in dest the assets using relative src path.
// Directories will recursively project its content.
// If there is no asset attached and relSrc is not "." then it returns an error.
// dest should exists.
func (pols *Policies) SaveAssetsTo(ctx context.Context, relSrc, dest string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't save assets to %s"), dest)

	log.Debugf(ctx, "export assets %q to %q", relSrc, dest)

	if pols.assets == nil {
		return errors.New(i18n.G("no assets attached"))
	}

	baseDir := filepath.Dir(relSrc)

	return pols.saveAssetsRecursively(relSrc, dest, baseDir)
}

func (pols *Policies) saveAssetsRecursively(relSrc, dest, baseDir string) (err error) {
	// zip doesn’t like final /, even when listing them return it.
	relSrc = strings.TrimSuffix(relSrc, "/")

	dstPath := filepath.Join(dest, strings.TrimPrefix(relSrc, baseDir))

	f, err := pols.assets.Open(relSrc)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		if err := os.MkdirAll(dstPath, 0700); err != nil {
			return err
		}

		// Remove any "." to match directory content
		relSrc = strings.TrimLeft(relSrc, "./")

		// Recursively list matching files and directory in that directory
		for _, zipF := range pols.assets.File {
			// add a final / to match directory content
			if relSrc != "" && !strings.HasSuffix(relSrc, "/") {
				relSrc = relSrc + "/"
			}
			if !strings.HasPrefix(zipF.Name, relSrc) || zipF.Name == relSrc {
				continue
			}
			if err := pols.saveAssetsRecursively(zipF.Name, dest, baseDir); err != nil {
				return err
			}
		}

		return nil
	}

	outF, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode())
	if err != nil {
		return err
	}
	defer outF.Close()

	if _, err = io.Copy(outF, f); err != nil {
		return err
	}

	return nil
}

// GetUniqueRules return order rules, with one entry per key for a given type.
// Returned file is a map of type to its entries.
func (pols Policies) GetUniqueRules() map[string][]entry.Entry {
	r := make(map[string][]entry.Entry)
	keys := make(map[string][]string)

	// Dedup entries, first GPO wins for a given type + key
	dedup := make(map[string]map[string]entry.Entry)
	seen := make(map[string]struct{})
	for _, gpo := range pols.GPOs {
		for t, entries := range gpo.Rules {
			if dedup[t] == nil {
				dedup[t] = make(map[string]entry.Entry)
			}
			for _, e := range entries {
				switch e.Strategy {
				case entry.StrategyAppend:
					// We skip disabled keys as we only append enabled one.
					if e.Disabled {
						continue
					}
					var keyAlreadySeen bool
					// If there is an existing value, prepend new value to it. We are analyzing GPOs in reverse order (closest first).
					if _, exists := seen[t+e.Key]; exists {
						keyAlreadySeen = true
						// We have seen a closest key which is an override. We don’t append furthest append values.
						if dedup[t][e.Key].Strategy != entry.StrategyAppend {
							continue
						}
						e.Value = e.Value + "\n" + dedup[t][e.Key].Value
						// Keep closest meta value.
						e.Meta = dedup[t][e.Key].Meta
					}
					dedup[t][e.Key] = e
					if keyAlreadySeen {
						continue
					}

				default:
					// override case
					if _, exists := seen[t+e.Key]; exists {
						continue
					}
					dedup[t][e.Key] = e
				}

				keys[t] = append(keys[t], e.Key)
				seen[t+e.Key] = struct{}{}
			}
		}
	}

	// For each t, order entries by ascii order
	for t := range dedup {
		var entries []entry.Entry
		sort.Strings(keys[t])
		for _, k := range keys[t] {
			entries = append(entries, dedup[t][k])
		}
		r[t] = entries
	}

	return r
}
