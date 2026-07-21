package certificate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerationPublicationFailuresNeverExposeMixedPair(t *testing.T) {
	tests := map[string]struct {
		configure func(string, *generationPublishOps)
		switched  bool
	}{
		"between key and certificate writes": {
			configure: func(_ string, ops *generationPublishOps) {
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
		"publication marker write": {
			configure: func(_ string, ops *generationPublishOps) {
				write := ops.writeFile
				ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
					if filepath.Base(path) == generationMarkerTemp {
						return errors.New("injected marker write failure")
					}
					return write(path, data, mode)
				}
			},
		},
		"publication marker fsync": {
			configure: func(_ string, ops *generationPublishOps) {
				write := ops.writeFile
				syncDir := ops.syncDir
				markerDirectory := ""
				ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
					err := write(path, data, mode)
					if err == nil && filepath.Base(path) == generationMarkerTemp {
						markerDirectory = filepath.Dir(path)
					}
					return err
				}
				ops.syncDir = func(path string) error {
					if markerDirectory != "" && filepath.Clean(path) == filepath.Clean(markerDirectory) {
						return errors.New("injected marker fsync failure")
					}
					return syncDir(path)
				}
			},
		},
		"publication marker rename": {
			configure: func(_ string, ops *generationPublishOps) {
				rename := ops.rename
				ops.rename = func(source, destination string) error {
					if filepath.Base(destination) == generationMarker {
						return errors.New("injected marker rename failure")
					}
					return rename(source, destination)
				}
			},
		},
		"during pointer rename": {
			configure: func(_ string, ops *generationPublishOps) {
				rename := ops.rename
				ops.rename = func(source, destination string) error {
					if filepath.Base(destination) == "current" {
						return errors.New("injected rename failure")
					}
					return rename(source, destination)
				}
			},
		},
		"final pointer fsync rolls back": {
			configure: func(root string, ops *generationPublishOps) {
				rename := ops.rename
				syncDir := ops.syncDir
				published := false
				failed := false
				ops.rename = func(source, destination string) error {
					err := rename(source, destination)
					if err == nil && filepath.Clean(destination) == filepath.Join(root, "current") {
						published = true
					}
					return err
				}
				ops.syncDir = func(path string) error {
					if published && !failed && filepath.Clean(path) == filepath.Clean(root) {
						failed = true
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
			test.configure(root, &ops)
			newKey, newCert := []byte("new-key"), []byte("new-certificate")
			result, err := publishCertificateGeneration(root, newKey, newCert, ops)
			require.Error(t, err)
			assert.Equal(t, test.switched, result.Switched)

			gotKey := mustReadFile(t, old.KeyFile)
			gotCert := mustReadFile(t, old.CertFile)
			assert.Equal(t, oldKey, gotKey)
			assert.Equal(t, oldCert, gotCert)
			if test.switched {
				assert.FileExists(t, result.MarkerFile)
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

	// The durable state still owns the original request material. The failed
	// state commit rolled the stable pointer back while retaining the staged
	// marker and generation for deterministic restart reconciliation.
	state, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, loadErr)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, uint32(95), state.Pending[0].RequestID)
	assert.Equal(t, pendingKey, mustReadFile(t, pending.KeyFile))
	assert.NoFileExists(t, filepath.Join(pending.GenerationRoot, "current"))
	markers, err := filepath.Glob(filepath.Join(pending.GenerationRoot, "generations", "*", generationMarker))
	require.NoError(t, err)
	require.Len(t, markers, 1)
	assert.FileExists(t, filepath.Join(filepath.Dir(markers[0]), generationKeyName))
	assert.FileExists(t, filepath.Join(filepath.Dir(markers[0]), generationCertName))

	// A fresh Manager reconciles the orphan before polling the same ID/key.
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

func TestGenerationRestartReconcilesDurableStateAuthority(t *testing.T) {
	tests := map[string]struct {
		advanceState bool
		removeMarker bool
	}{
		"state still selects previous generation": {},
		"state selects published generation": {
			advanceState: true,
		},
		"state selects published generation after marker removal": {
			advanceState: true,
			removeMarker: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			root := filepath.Join(stateDir, "private", "certs", "target")
			old, err := publishCertificateGeneration(root, []byte("old-key"), []byte("old-cert"), defaultGenerationPublishOps())
			require.NoError(t, err)
			require.NoError(t, finalizeGenerationPublication(old))
			state := generationTestState(t, old)
			require.NoError(t, saveState(stateDir, state))

			newGeneration, err := publishCertificateGeneration(root, []byte("new-key"), []byte("new-cert"), defaultGenerationPublishOps())
			require.NoError(t, err)
			if test.advanceState {
				state.CAs[0].Templates[0].GenerationDir = newGeneration.Directory
				require.NoError(t, saveState(stateDir, state))
				if test.removeMarker {
					require.NoError(t, finalizeGenerationPublication(newGeneration))
				}
				require.NoError(t, selectGenerationPointer(root, old.Directory, defaultGenerationPublishOps()))
			}

			require.NoError(t, reconcileGenerationPublications(stateDir, defaultGenerationPublishOps()))
			want := old
			wantKey, wantCert := []byte("old-key"), []byte("old-cert")
			removed := newGeneration.Directory
			if test.advanceState {
				want = newGeneration
				wantKey, wantCert = []byte("new-key"), []byte("new-cert")
				removed = old.Directory
			}
			assert.Equal(t, filepath.Clean(want.Directory), filepath.Clean(mustResolvePointer(t, want.Pointer)))
			assert.Equal(t, wantKey, mustReadFile(t, want.KeyFile))
			assert.Equal(t, wantCert, mustReadFile(t, want.CertFile))
			assert.NoDirExists(t, removed)
			markers, err := filepath.Glob(filepath.Join(root, "generations", "*", generationMarker))
			require.NoError(t, err)
			assert.Empty(t, markers)
		})
	}
}

func TestGenerationRollbackFailuresReconcileOnRestart(t *testing.T) {
	for _, failure := range []string{"rename", "fsync"} {
		t.Run(failure, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			root := filepath.Join(stateDir, "private", "certs", "target")
			old, err := publishCertificateGeneration(root, []byte("old-key"), []byte("old-cert"), defaultGenerationPublishOps())
			require.NoError(t, err)
			require.NoError(t, finalizeGenerationPublication(old))
			require.NoError(t, saveState(stateDir, generationTestState(t, old)))

			ops := defaultGenerationPublishOps()
			rename := ops.rename
			syncDir := ops.syncDir
			renameAttempts := 0
			successfulRenames := 0
			publishSyncFailed := false
			ops.rename = func(source, destination string) error {
				if filepath.Clean(destination) == filepath.Join(root, "current") {
					renameAttempts++
					if failure == "rename" && renameAttempts > 1 {
						return errors.New("injected rollback rename failure")
					}
				}
				err := rename(source, destination)
				if err == nil && filepath.Clean(destination) == filepath.Join(root, "current") {
					successfulRenames++
				}
				return err
			}
			ops.syncDir = func(path string) error {
				if filepath.Clean(path) == filepath.Clean(root) && successfulRenames == 1 && !publishSyncFailed {
					publishSyncFailed = true
					return errors.New("injected final pointer fsync failure")
				}
				if failure == "fsync" && filepath.Clean(path) == filepath.Clean(root) && successfulRenames > 1 {
					return errors.New("injected rollback fsync failure")
				}
				return syncDir(path)
			}

			publication, err := publishCertificateGeneration(root, []byte("new-key"), []byte("new-cert"), ops)
			require.Error(t, err)
			assert.True(t, publication.Switched)
			assert.FileExists(t, publication.MarkerFile)
			key := mustReadFile(t, old.KeyFile)
			cert := mustReadFile(t, old.CertFile)
			assert.Equal(t, string(key[:3]), string(cert[:3]), "rollback failure exposed a mixed generation")

			require.NoError(t, reconcileGenerationPublications(stateDir, defaultGenerationPublishOps()))
			assert.Equal(t, filepath.Clean(old.Directory), filepath.Clean(mustResolvePointer(t, old.Pointer)))
			assert.Equal(t, []byte("old-key"), mustReadFile(t, old.KeyFile))
			assert.Equal(t, []byte("old-cert"), mustReadFile(t, old.CertFile))
			assert.NoDirExists(t, publication.Directory)
		})
	}
}

func TestGenerationRestartCleansInterruptedTemporaryEntries(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	root := filepath.Join(stateDir, "private", "certs", "target")
	old, err := publishCertificateGeneration(root, []byte("old-key"), []byte("old-cert"), defaultGenerationPublishOps())
	require.NoError(t, err)
	require.NoError(t, finalizeGenerationPublication(old))
	require.NoError(t, saveState(stateDir, generationTestState(t, old)))

	interrupted, err := os.MkdirTemp(filepath.Join(root, "generations"), "generation-")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(interrupted, generationKeyName), []byte("new-key"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(interrupted, generationCertName), []byte("new-cert"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(interrupted, generationMarkerTemp), []byte("partial marker"), 0600))
	relative, err := filepath.Rel(root, interrupted)
	require.NoError(t, err)
	pointerTemp := filepath.Join(root, ".current.tmp.crash")
	require.NoError(t, os.Symlink(relative, pointerTemp))

	require.NoError(t, reconcileGenerationPublications(stateDir, defaultGenerationPublishOps()))
	assert.NoFileExists(t, pointerTemp)
	assert.NoDirExists(t, interrupted)
	assert.Equal(t, filepath.Clean(old.Directory), filepath.Clean(mustResolvePointer(t, old.Pointer)))
	assert.Equal(t, []byte("old-key"), mustReadFile(t, old.KeyFile))
	assert.Equal(t, []byte("old-cert"), mustReadFile(t, old.CertFile))
}

func TestGenerationEntryMutationsSyncContainingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private", "certs", "target")
	ops := defaultGenerationPublishOps()
	base := ops
	var events []string
	recordMutation := func(path string) {
		events = append(events, "mutation|"+filepath.Clean(path))
	}
	ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if err := base.writeFile(path, data, mode); err != nil {
			return err
		}
		recordMutation(path)
		return nil
	}
	ops.mkdirTemp = func(directory, pattern string) (string, error) {
		path, err := base.mkdirTemp(directory, pattern)
		if err == nil {
			recordMutation(path)
		}
		return path, err
	}
	ops.symlink = func(target, path string) error {
		if err := base.symlink(target, path); err != nil {
			return err
		}
		recordMutation(path)
		return nil
	}
	ops.rename = func(source, destination string) error {
		if err := base.rename(source, destination); err != nil {
			return err
		}
		recordMutation(destination)
		return nil
	}
	ops.remove = func(path string) error {
		if err := base.remove(path); err != nil {
			return err
		}
		recordMutation(path)
		return nil
	}
	ops.syncDir = func(path string) error {
		events = append(events, "sync|"+filepath.Clean(path))
		return base.syncDir(path)
	}

	publication, err := publishCertificateGeneration(root, []byte("key"), []byte("cert"), ops)
	require.NoError(t, err)
	require.NoError(t, finalizeGenerationPublicationWithOps(publication, ops))
	require.NoError(t, selectGenerationPointer(root, "", ops))
	require.NoError(t, removeStagedGeneration(publication.Directory, ops))

	for index, event := range events {
		if !strings.HasPrefix(event, "mutation|") {
			continue
		}
		path := strings.TrimPrefix(event, "mutation|")
		require.Less(t, index+1, len(events), "mutation %s had no following directory fsync", path)
		assert.Equal(t, "sync|"+filepath.Clean(filepath.Dir(path)), events[index+1], "mutation %s was not immediately directory-synced", path)
	}
	for _, directory := range []string{filepath.Dir(root), root, filepath.Join(root, "generations"), publication.Directory} {
		assert.Contains(t, events, "sync|"+filepath.Clean(directory))
	}
}

func TestPendingPublicationFailuresRetryPairConsistently(t *testing.T) {
	tests := map[string]func(string, *Manager){
		"marker write": func(_ string, manager *Manager) {
			write := manager.generationOps.writeFile
			manager.generationOps.writeFile = func(path string, data []byte, mode os.FileMode) error {
				if filepath.Base(path) == generationMarkerTemp {
					return errors.New("injected marker write failure")
				}
				return write(path, data, mode)
			}
		},
		"marker fsync": func(_ string, manager *Manager) {
			write := manager.generationOps.writeFile
			syncDir := manager.generationOps.syncDir
			markerDirectory := ""
			manager.generationOps.writeFile = func(path string, data []byte, mode os.FileMode) error {
				err := write(path, data, mode)
				if err == nil && filepath.Base(path) == generationMarkerTemp {
					markerDirectory = filepath.Dir(path)
				}
				return err
			}
			manager.generationOps.syncDir = func(path string) error {
				if markerDirectory != "" && filepath.Clean(path) == filepath.Clean(markerDirectory) {
					return errors.New("injected marker fsync failure")
				}
				return syncDir(path)
			}
		},
		"marker rename": func(_ string, manager *Manager) {
			rename := manager.generationOps.rename
			manager.generationOps.rename = func(source, destination string) error {
				if filepath.Base(destination) == generationMarker {
					return errors.New("injected marker rename failure")
				}
				return rename(source, destination)
			}
		},
		"pointer rename": func(_ string, manager *Manager) {
			rename := manager.generationOps.rename
			manager.generationOps.rename = func(source, destination string) error {
				if filepath.Base(destination) == "current" {
					return errors.New("injected pointer rename failure")
				}
				return rename(source, destination)
			}
		},
		"final pointer fsync": func(root string, manager *Manager) {
			injectFinalPointerSyncFailure(root, manager, false)
		},
		"uncertain rollback": func(root string, manager *Manager) {
			injectFinalPointerSyncFailure(root, manager, true)
		},
		"state save": func(_ string, manager *Manager) {
			manager.saveEnrollmentState = func(string, *enrollmentState) error {
				return errors.New("injected state save failure")
			}
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir, trustDir, caDER, fake, pending := pendingGenerationFixture(t)
			manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			configure(pending.GenerationRoot, manager)
			require.Error(t, manager.enroll(context.Background(), mgrTestObject))

			state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			require.Len(t, state.Pending, 1)
			assert.Equal(t, pending.RequestID, state.Pending[0].RequestID)
			assertStableGenerationPair(t, pending.GenerationRoot)

			manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
			state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			require.Empty(t, state.Pending)
			require.Len(t, state.CAs, 1)
			assertStableGenerationPair(t, pending.GenerationRoot)
			assert.Equal(t, 1, fake.submits)
			assert.Equal(t, 2, fake.polls)
		})
	}
}

func TestCommittedStateSurvivesMarkerFinalizationFailures(t *testing.T) {
	for _, failure := range []string{"remove", "fsync"} {
		t.Run(failure, func(t *testing.T) {
			stateDir, trustDir, caDER, fake, pending := pendingGenerationFixture(t)
			manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			remove := manager.generationOps.remove
			syncDir := manager.generationOps.syncDir
			removedMarkerDir := ""
			manager.generationOps.remove = func(path string) error {
				if filepath.Base(path) != generationMarker {
					return remove(path)
				}
				if failure == "remove" {
					return errors.New("injected marker removal failure")
				}
				err := remove(path)
				if err == nil {
					removedMarkerDir = filepath.Dir(path)
				}
				return err
			}
			manager.generationOps.syncDir = func(path string) error {
				if failure == "fsync" && removedMarkerDir != "" &&
					filepath.Clean(path) == filepath.Clean(removedMarkerDir) {
					return errors.New("injected marker parent fsync failure")
				}
				return syncDir(path)
			}

			require.Error(t, manager.enroll(context.Background(), mgrTestObject))
			state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			require.Empty(t, state.Pending)
			require.Len(t, state.CAs, 1)
			assertStableGenerationPair(t, pending.GenerationRoot)

			manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
			state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			require.Empty(t, state.Pending)
			markers, err := filepath.Glob(filepath.Join(pending.GenerationRoot, "generations", "*", generationMarker))
			require.NoError(t, err)
			assert.Empty(t, markers)
			assertStableGenerationPair(t, pending.GenerationRoot)
			assert.Equal(t, 1, fake.submits)
			assert.Equal(t, 1, fake.polls)
		})
	}
}

func TestRestartRejectsMaliciousPublicationMarkerBeforeRequest(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	root := filepath.Join(stateDir, "private", "certs", "target")
	old, err := publishCertificateGeneration(root, []byte("old-key"), []byte("old-cert"), defaultGenerationPublishOps())
	require.NoError(t, err)
	require.NoError(t, finalizeGenerationPublication(old))
	require.NoError(t, saveState(stateDir, generationTestState(t, old)))
	newGeneration, err := publishCertificateGeneration(root, []byte("new-key"), []byte("new-cert"), defaultGenerationPublishOps())
	require.NoError(t, err)

	external := filepath.Join(t.TempDir(), "external-generation")
	require.NoError(t, os.MkdirAll(external, 0700))
	sentinel := filepath.Join(external, "sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("foreign"), 0600))
	markerData, err := json.Marshal(publicationMarker{
		CreatedAt:          time.Now().UTC(),
		PreviousGeneration: external,
		Generation:         newGeneration.Directory,
		GenerationPointer:  newGeneration.Pointer,
		KeyFile:            newGeneration.KeyFile,
		CertFile:           newGeneration.CertFile,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(newGeneration.MarkerFile, markerData, 0600))

	_, _, caDER := mgrTestCA(t)
	requests := 0
	manager := lifecycleManager(t, stateDir, filepath.Join(t.TempDir(), "trust"), caDER, RequesterFunc(func(context.Context, Request) (Response, error) {
		requests++
		return Response{}, errors.New("request must not run")
	}))
	err = manager.enroll(context.Background(), mgrTestObject)
	require.ErrorIs(t, err, errGenerationCorruption)
	assert.Zero(t, requests)
	assert.FileExists(t, sentinel)
	assert.DirExists(t, old.Directory)
	assert.DirExists(t, newGeneration.Directory)
	assert.FileExists(t, newGeneration.MarkerFile)
	assert.Equal(t, []byte("new-key"), mustReadFile(t, newGeneration.KeyFile))
	assert.Equal(t, []byte("new-cert"), mustReadFile(t, newGeneration.CertFile))
}

func pendingGenerationFixture(t *testing.T) (string, string, []byte, *lifecycleFake, pendingEnrollment) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	fake := &lifecycleFake{
		t: t, caCert: caCert, caKey: caKey, autoIssue: true,
		submitResponse: Response{Disposition: DispositionPending, RequestID: 215},
		pollResponse:   Response{Disposition: DispositionIssued, RequestID: 215},
	}
	manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	require.ErrorIs(t, manager.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 1)
	return stateDir, trustDir, caDER, fake, state.Pending[0]
}

func injectFinalPointerSyncFailure(root string, manager *Manager, failRollback bool) {
	syncDir := manager.generationOps.syncDir
	remove := manager.generationOps.remove
	rename := manager.generationOps.rename
	published := false
	failed := false
	manager.generationOps.rename = func(source, destination string) error {
		err := rename(source, destination)
		if err == nil && filepath.Clean(destination) == filepath.Join(root, "current") {
			published = true
		}
		return err
	}
	manager.generationOps.syncDir = func(path string) error {
		if published && !failed && filepath.Clean(path) == filepath.Clean(root) {
			failed = true
			return errors.New("injected final pointer fsync failure")
		}
		return syncDir(path)
	}
	if failRollback {
		manager.generationOps.remove = func(path string) error {
			if failed && filepath.Clean(path) == filepath.Join(root, "current") {
				return errors.New("injected rollback unlink failure")
			}
			return remove(path)
		}
	}
}

func assertStableGenerationPair(t *testing.T, root string) {
	t.Helper()
	pointer := filepath.Join(root, "current")
	if _, err := os.Lstat(pointer); os.IsNotExist(err) {
		return
	}
	directory := mustResolvePointer(t, pointer)
	certificate := parseCertFile(filepath.Join(directory, generationCertName))
	require.NotNil(t, certificate)
	match, err := publicKeysMatch(certificate, enrolledTemplate{
		KeyFile:           filepath.Join(pointer, generationKeyName),
		CertFile:          filepath.Join(pointer, generationCertName),
		GenerationRoot:    root,
		GenerationPointer: pointer,
		GenerationDir:     directory,
	})
	require.NoError(t, err)
	assert.True(t, match)
}

func generationTestState(t *testing.T, paths generationPaths) *enrollmentState {
	t.Helper()
	identity, err := enrollmentMachineIdentity(mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	return &enrollmentState{
		ObjectName: mgrTestObject,
		Identity:   identity.dnsName,
		Domain:     mgrTestDomain,
		CAs: []enrolledCA{{
			Name:     "TestCA",
			Hostname: "ca.example.com",
			Templates: []enrolledTemplate{{
				Nickname:          "TestCA.Machine",
				Template:          "Machine",
				KeyFile:           paths.KeyFile,
				CertFile:          paths.CertFile,
				GenerationRoot:    paths.Root,
				GenerationPointer: paths.Pointer,
				GenerationDir:     paths.Directory,
			}},
		}},
	}
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
