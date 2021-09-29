package gdm

import (
	"context"
	"strings"
	"sync"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"golang.org/x/sync/errgroup"
)

// Manager prevents running multiple gdm update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	mu    sync.RWMutex
	dconf *dconf.Manager
}

type options struct {
	dconf *dconf.Manager
}
type option func(*options) error

// WithDconf specifies a personalized dconf manager.
func WithDconf(m *dconf.Manager) func(o *options) error {
	return func(o *options) error {
		o.dconf = m
		return nil
	}
}

// New returns a new manager for gdm policy handlers.
func New(opts ...option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("can't create a new gdm handler manager"))

	// defaults
	args := options{
		dconf: &dconf.Manager{},
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	return &Manager{
		dconf: args.dconf,
	}, nil
}

// ApplyPolicy generates a dconf computer or user policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply gdm policy"))

	m.mu.RLock()

	log.Debug(ctx, "ApplyPolicy gdm policy")

	// Order all entries by keytype for gdm
	sortedEntries := make(map[string][]entry.Entry)
	for _, e := range entries {
		keyType := strings.Split(e.Key, "/")[0]
		e.Key = strings.TrimPrefix(e.Key, keyType+"/")
		sortedEntries[keyType] = append(sortedEntries[keyType], e)
	}

	var g errgroup.Group
	g.Go(func() error { return m.dconf.ApplyPolicy(ctx, "gdm", false, sortedEntries["dconf"]) })

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}
