package certificate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxPublicationMarkerBytes = 64 << 10

var errGenerationCorruption = errors.New("certificate generation transaction is corrupt")

type generationAuthority struct {
	selected map[string]string
	roots    map[string]struct{}
}

func reconcileGenerationPublications(stateDir string, ops generationPublishOps) error {
	if !ops.complete() {
		return fmt.Errorf("certificate generation reconciler is incomplete")
	}
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	authority, err := loadGenerationAuthority(stateDir)
	if err != nil {
		return fmt.Errorf("%w: loading durable generation authority: %w", errGenerationCorruption, err)
	}
	if err := discoverGenerationRoots(stateDir, &authority); err != nil {
		return fmt.Errorf("%w: discovering generation roots: %w", errGenerationCorruption, err)
	}
	roots := make([]string, 0, len(authority.roots))
	for root := range authority.roots {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		if err := reconcileGenerationRoot(stateDir, root, authority.selected[root], ops); err != nil {
			return fmt.Errorf("%w: reconciling %s: %w", errGenerationCorruption, root, err)
		}
	}
	return nil
}

func loadGenerationAuthority(stateDir string) (generationAuthority, error) {
	authority := generationAuthority{
		selected: make(map[string]string),
		roots:    make(map[string]struct{}),
	}
	stateFiles, err := filepath.Glob(filepath.Join(stateDir, "certs", "state_*.json"))
	if err != nil {
		return generationAuthority{}, err
	}
	type enumeratedState struct {
		state     *enrollmentState
		canonical bool
	}
	states := make(map[string]enumeratedState)
	for _, path := range stateFiles {
		state, _, err := readStateFile(path)
		if err != nil {
			return generationAuthority{}, fmt.Errorf("reading enrollment state %s: %w", path, err)
		}
		if err := validateEnumeratedState(state); err != nil {
			return generationAuthority{}, fmt.Errorf("validating enrollment state %s: %w", path, err)
		}
		if err := validateGenerationStatePaths(stateDir, state); err != nil {
			return generationAuthority{}, fmt.Errorf("validating generation paths in %s: %w", path, err)
		}
		canonical := isCanonicalStatePath(stateDir, path, state)
		if !canonical && !isLegacyStatePath(stateDir, path, state) {
			continue
		}
		key := stateOwnerKey(state)
		current, found := states[key]
		if !found || canonical && !current.canonical {
			states[key] = enumeratedState{state: state, canonical: canonical}
		}
	}
	for _, entry := range states {
		for _, ca := range entry.state.CAs {
			for _, template := range ca.Templates {
				if template.GenerationRoot == "" && template.GenerationDir == "" && template.GenerationPointer == "" {
					continue
				}
				root, err := filepath.Abs(template.GenerationRoot)
				if err != nil {
					return generationAuthority{}, err
				}
				directory, err := filepath.Abs(template.GenerationDir)
				if err != nil {
					return generationAuthority{}, err
				}
				if selected, found := authority.selected[root]; found && filepath.Clean(selected) != filepath.Clean(directory) {
					return generationAuthority{}, fmt.Errorf("durable states select conflicting generations under %s", root)
				}
				authority.selected[root] = directory
				authority.roots[root] = struct{}{}
			}
		}
		for _, pending := range entry.state.Pending {
			root, err := filepath.Abs(pending.GenerationRoot)
			if err != nil {
				return generationAuthority{}, err
			}
			authority.roots[root] = struct{}{}
		}
	}
	return authority, nil
}

func discoverGenerationRoots(stateDir string, authority *generationAuthority) error {
	privateRoot, err := filepath.Abs(filepath.Join(stateDir, "private", "certs"))
	if err != nil {
		return err
	}
	info, err := os.Lstat(privateRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private certificate root is not a regular directory")
	}
	entries, err := os.ReadDir(privateRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(privateRoot, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private certificate root contains symlink %s", path)
		}
		if !info.IsDir() {
			continue
		}
		generations := filepath.Join(path, "generations")
		generationsInfo, err := os.Lstat(generations)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !generationsInfo.IsDir() || generationsInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular generations directory", generations)
		}
		authority.roots[path] = struct{}{}
	}
	return nil
}

func reconcileGenerationRoot(stateDir, root, desired string, ops generationPublishOps) error {
	privateRoot, err := filepath.Abs(filepath.Join(stateDir, "private", "certs"))
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	if !pathWithin(privateRoot, root) || filepath.Clean(root) == filepath.Clean(privateRoot) {
		return fmt.Errorf("generation root is outside ADSys private state")
	}
	if err := validateGenerationRootComponents(privateRoot, root); err != nil {
		return err
	}
	generations := filepath.Join(root, "generations")
	info, err := os.Lstat(generations)
	if os.IsNotExist(err) {
		if desired != "" {
			return fmt.Errorf("durable state selects a missing generations directory")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generations path is not a regular directory")
	}

	entries, err := os.ReadDir(generations)
	if err != nil {
		return err
	}
	var markerPaths []string
	for _, entry := range entries {
		directory := filepath.Join(generations, entry.Name())
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generation entry %s is not a regular directory", directory)
		}
		marker := filepath.Join(directory, generationMarker)
		markerInfo, err := os.Lstat(marker)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !markerInfo.Mode().IsRegular() {
			return fmt.Errorf("publication marker %s is not a regular file", marker)
		}
		markerPaths = append(markerPaths, marker)
	}
	sort.Strings(markerPaths)
	markers := make([]generationPaths, 0, len(markerPaths))
	for _, markerPath := range markerPaths {
		paths, _, err := readAndValidatePublicationMarker(privateRoot, markerPath)
		if err != nil {
			return err
		}
		if filepath.Clean(paths.Root) != filepath.Clean(root) {
			return fmt.Errorf("publication marker root does not match its location")
		}
		markers = append(markers, paths)
	}
	if desired != "" {
		if err := validateGenerationDirectory(root, desired); err != nil {
			return fmt.Errorf("durable state generation is incomplete: %w", err)
		}
	}
	if err := cleanupGenerationPointerTemps(root, generations, ops); err != nil {
		return err
	}
	for _, paths := range markers {
		if err := selectGenerationPointer(root, desired, ops); err != nil {
			return fmt.Errorf("selecting durable-state generation: %w", err)
		}
		if err := finalizeGenerationPublicationWithOps(paths, ops); err != nil {
			return err
		}
		if filepath.Clean(paths.Directory) != filepath.Clean(desired) {
			if err := removeStagedGeneration(paths.Directory, ops); err != nil {
				return fmt.Errorf("cleaning rolled-back generation: %w", err)
			}
		} else if paths.PreviousDirectory != "" &&
			filepath.Clean(paths.PreviousDirectory) != filepath.Clean(desired) {
			if err := removeStagedGeneration(paths.PreviousDirectory, ops); err != nil {
				return fmt.Errorf("cleaning previous committed generation: %w", err)
			}
		}
	}

	if desired != "" {
		if err := validateGenerationDirectory(root, desired); err != nil {
			return fmt.Errorf("durable state generation is incomplete: %w", err)
		}
	}
	if err := selectGenerationPointer(root, desired, ops); err != nil {
		return fmt.Errorf("enforcing durable-state generation pointer: %w", err)
	}
	return garbageCollectGenerationRoot(generations, desired, ops)
}

func cleanupGenerationPointerTemps(root, generations string, ops generationPublishOps) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var temporaryPointers []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".current.tmp.") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("temporary generation pointer %s is not a symlink", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(root, target)
		}
		target, err = filepath.Abs(target)
		if err != nil {
			return err
		}
		if !pathWithin(generations, target) || filepath.Clean(target) == filepath.Clean(generations) {
			return fmt.Errorf("temporary generation pointer %s targets a path outside its owned generations", path)
		}
		if err := validateGenerationDirectory(root, target); err != nil {
			return fmt.Errorf("temporary generation pointer %s has an incomplete target: %w", path, err)
		}
		temporaryPointers = append(temporaryPointers, path)
	}
	for _, path := range temporaryPointers {
		if err := removePathAndSync(path, ops); err != nil {
			return fmt.Errorf("removing temporary generation pointer %s: %w", path, err)
		}
	}
	return nil
}

func readAndValidatePublicationMarker(privateRoot, path string) (generationPaths, publicationMarker, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPublicationMarkerBytes {
		return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker has an invalid type or size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker publicationMarker
	if err := decoder.Decode(&marker); err != nil {
		return generationPaths{}, publicationMarker{}, fmt.Errorf("decoding publication marker: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	directory, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	generations := filepath.Dir(directory)
	root := filepath.Dir(generations)
	privateRoot, err = filepath.Abs(privateRoot)
	if err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	if !pathWithin(privateRoot, root) || filepath.Clean(root) == filepath.Clean(privateRoot) ||
		filepath.Base(generations) != "generations" {
		return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker is outside an owned generation root")
	}
	if err := validateGenerationRootComponents(privateRoot, root); err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	expectedPointer := filepath.Join(root, "current")
	expectedKey := filepath.Join(expectedPointer, generationKeyName)
	expectedCert := filepath.Join(expectedPointer, generationCertName)
	expectedMarker := filepath.Join(directory, generationMarker)
	for name, pair := range map[string][2]string{
		"generation":         {marker.Generation, directory},
		"generation pointer": {marker.GenerationPointer, expectedPointer},
		"key file":           {marker.KeyFile, expectedKey},
		"certificate file":   {marker.CertFile, expectedCert},
	} {
		if !filepath.IsAbs(pair[0]) || filepath.Clean(pair[0]) != pair[0] ||
			filepath.Clean(pair[0]) != filepath.Clean(pair[1]) {
			return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker %s does not match its owned location", name)
		}
	}
	if marker.CreatedAt.IsZero() {
		return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker creation time is missing")
	}
	if err := validateGenerationDirectory(root, directory); err != nil {
		return generationPaths{}, publicationMarker{}, err
	}
	previous := ""
	if marker.PreviousGeneration != "" {
		if !filepath.IsAbs(marker.PreviousGeneration) || filepath.Clean(marker.PreviousGeneration) != marker.PreviousGeneration {
			return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker previous generation is not canonical")
		}
		previous = marker.PreviousGeneration
		if filepath.Dir(previous) != generations || filepath.Clean(previous) == filepath.Clean(directory) {
			return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker previous generation is outside its owned root")
		}
		previousInfo, err := os.Lstat(previous)
		if err != nil && !os.IsNotExist(err) {
			return generationPaths{}, publicationMarker{}, err
		}
		if err == nil && (!previousInfo.IsDir() || previousInfo.Mode()&os.ModeSymlink != 0) {
			return generationPaths{}, publicationMarker{}, fmt.Errorf("publication marker previous generation is not a regular directory")
		}
	}
	return generationPaths{
		Root:              root,
		Pointer:           expectedPointer,
		Directory:         directory,
		PreviousDirectory: previous,
		KeyFile:           expectedKey,
		CertFile:          expectedCert,
		MarkerFile:        expectedMarker,
		Switched:          true,
	}, marker, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("publication marker contains trailing JSON")
		}
		return fmt.Errorf("decoding publication marker trailer: %w", err)
	}
	return nil
}

func garbageCollectGenerationRoot(generations, desired string, ops generationPublishOps) error {
	entries, err := os.ReadDir(generations)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		directory := filepath.Join(generations, entry.Name())
		if filepath.Clean(directory) == filepath.Clean(desired) {
			continue
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generation entry %s is not a regular directory", directory)
		}
		if _, err := os.Lstat(filepath.Join(directory, generationMarker)); err == nil {
			return fmt.Errorf("unreconciled publication marker remains in %s", directory)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := removeStagedGeneration(directory, ops); err != nil {
			return fmt.Errorf("garbage collecting generation %s: %w", directory, err)
		}
	}
	return nil
}
