package certificate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerationPublicationFailuresNeverExposeMixedPair(t *testing.T) {
	tests := map[string]struct {
		configure func(*generationPublishOps)
		switched  bool
	}{
		"between key and certificate writes": {
			configure: func(ops *generationPublishOps) {
				write := ops.writeFile
				calls := 0
				ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
					calls++
					if calls == 2 {
						return errors.New("injected certificate write failure")
					}
					return write(path, data, mode)
				}
			},
		},
		"staged generation fsync": {
			configure: func(ops *generationPublishOps) {
				ops.syncDir = func(string) error { return errors.New("injected staged fsync failure") }
			},
		},
		"before pointer rename": {
			configure: func(ops *generationPublishOps) {
				syncDir := ops.syncDir
				calls := 0
				ops.syncDir = func(path string) error {
					calls++
					if calls == 3 {
						return errors.New("injected pointer fsync failure")
					}
					return syncDir(path)
				}
			},
		},
		"during pointer rename": {
			configure: func(ops *generationPublishOps) {
				ops.rename = func(string, string) error { return errors.New("injected rename failure") }
			},
		},
		"after pointer rename fsync": {
			configure: func(ops *generationPublishOps) {
				syncDir := ops.syncDir
				calls := 0
				ops.syncDir = func(path string) error {
					calls++
					if calls == 4 {
						return errors.New("injected post-rename fsync failure")
					}
					return syncDir(path)
				}
			},
			switched: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "private", "certs", "target")
			oldKey, oldCert := []byte("old-key"), []byte("old-certificate")
			old, err := publishCertificateGeneration(root, oldKey, oldCert, defaultGenerationPublishOps())
			require.NoError(t, err)
			require.NoError(t, finalizeGenerationPublication(old))
			keyInfo, err := os.Lstat(filepath.Join(old.Directory, generationKeyName))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
			certInfo, err := os.Lstat(filepath.Join(old.Directory, generationCertName))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0644), certInfo.Mode().Perm())
			pointerInfo, err := os.Lstat(old.Pointer)
			require.NoError(t, err)
			assert.NotZero(t, pointerInfo.Mode()&os.ModeSymlink)

			ops := defaultGenerationPublishOps()
			test.configure(&ops)
			newKey, newCert := []byte("new-key"), []byte("new-certificate")
			result, err := publishCertificateGeneration(root, newKey, newCert, ops)
			require.Error(t, err)
			assert.Equal(t, test.switched, result.Switched)

			gotKey := mustReadFile(t, old.KeyFile)
			gotCert := mustReadFile(t, old.CertFile)
			if test.switched {
				assert.Equal(t, newKey, gotKey)
				assert.Equal(t, newCert, gotCert)
				assert.FileExists(t, result.MarkerFile)
			} else {
				assert.Equal(t, oldKey, gotKey)
				assert.Equal(t, oldCert, gotCert)
			}
			assert.Equal(t, string(gotKey[:3]), string(gotCert[:3]), "stable paths exposed different generations")
		})
	}
}

func TestPollStateSaveFailureRetainsRecoverablePairAndRequest(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	fake := &lifecycleFake{
		t: t, caCert: caCert, caKey: caKey, autoIssue: true,
		submitResponse: Response{Disposition: DispositionPending, RequestID: 95},
		pollResponse:   Response{Disposition: DispositionIssued, RequestID: 95},
	}
	manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	require.ErrorIs(t, manager.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	pending := state.Pending[0]
	pendingKey := mustReadFile(t, pending.KeyFile)

	manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	manager.saveEnrollmentState = func(string, *enrollmentState) error {
		return errors.New("injected state save failure")
	}
	err = manager.enroll(context.Background(), mgrTestObject)
	require.ErrorContains(t, err, "injected state save failure")

	// The durable state still owns the original request material, while the
	// single live pointer exposes a complete pair from that same private key.
	state, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, loadErr)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, uint32(95), state.Pending[0].RequestID)
	assert.Equal(t, pendingKey, mustReadFile(t, pending.KeyFile))
	keyPath := filepath.Join(pending.GenerationRoot, "current", generationKeyName)
	certPath := filepath.Join(pending.GenerationRoot, "current", generationCertName)
	assert.FileExists(t, keyPath)
	assert.FileExists(t, certPath)
	certificate := parseCertFile(certPath)
	require.NotNil(t, certificate)
	match, err := publicKeysMatch(certificate, enrolledTemplate{
		KeyFile:           keyPath,
		CertFile:          certPath,
		GenerationRoot:    pending.GenerationRoot,
		GenerationPointer: filepath.Join(pending.GenerationRoot, "current"),
		GenerationDir:     mustResolvePointer(t, filepath.Join(pending.GenerationRoot, "current")),
	})
	require.NoError(t, err)
	assert.True(t, match)
	assert.FileExists(t, filepath.Join(mustResolvePointer(t, filepath.Join(pending.GenerationRoot, "current")), generationMarker))

	// Retrying from a fresh Manager polls the same ID/key and commits cleanly.
	manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, state.Pending)
	require.Len(t, state.CAs, 1)
	assert.Equal(t, 1, fake.submits)
	assert.Equal(t, 2, fake.polls)
	assert.WithinDuration(t, time.Now(), state.UpdatedAt, time.Minute)
}

func mustResolvePointer(t *testing.T, pointer string) string {
	t.Helper()
	target, err := os.Readlink(pointer)
	require.NoError(t, err)
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(pointer), target)
	}
	return filepath.Clean(target)
}
