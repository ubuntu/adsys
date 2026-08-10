package certificate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	generationKeyName    = "private.key"
	generationCertName   = "certificate.crt"
	generationMarker     = "publication.json"
	generationMarkerTemp = ".publication.json.tmp"
)

type generationPaths struct {
	Root              string
	Pointer           string
	Directory         string
	PreviousDirectory string
	KeyFile           string
	CertFile          string
	MarkerFile        string
	Switched          bool
}

type generationPublishOps struct {
	writeFile func(string, []byte, os.FileMode) error
	syncDir   func(string) error
	symlink   func(string, string) error
	rename    func(string, string) error
	remove    func(string) error
	mkdirTemp func(string, string) (string, error)
}

func defaultGenerationPublishOps() generationPublishOps {
	return generationPublishOps{
		writeFile: writeExclusiveSyncedFile,
		syncDir:   syncDirectory,
		symlink:   os.Symlink,
		rename:    os.Rename,
		remove:    os.Remove,
		mkdirTemp: os.MkdirTemp,
	}
}

type publicationMarker struct {
	CreatedAt          time.Time `json:"created_at"`
	PreviousGeneration string    `json:"previous_generation,omitempty"`
	Generation         string    `json:"generation"`
	GenerationPointer  string    `json:"generation_pointer"`
	KeyFile            string    `json:"key_file"`
	CertFile           string    `json:"cert_file"`
}

// publishCertificateGeneration stages a complete immutable key/certificate
// generation and exposes both through one atomically replaced directory
// symlink. The publication marker remains until the caller durably commits the
// corresponding state. Any post-rename failure is rolled back to the previous
// pointer before the error is returned; the marker is retained so restart
// reconciliation can resolve an uncertain rollback.
func publishCertificateGeneration(root string, keyPEM, certPEM []byte, ops generationPublishOps) (result generationPaths, err error) {
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return generationPaths{}, fmt.Errorf("refusing to publish an incomplete certificate generation")
	}
	if !ops.complete() {
		return generationPaths{}, fmt.Errorf("certificate generation publisher is incomplete")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return generationPaths{}, fmt.Errorf("resolving certificate generation root: %w", err)
	}
	if err := ensurePrivateDirectoryWithSync(root, ops.syncDir); err != nil {
		return generationPaths{}, err
	}
	generationsDir := filepath.Join(root, "generations")
	if err := ensurePrivateDirectoryWithSync(generationsDir, ops.syncDir); err != nil {
		return generationPaths{}, err
	}

	previousGeneration, err := inspectGenerationPointer(root)
	if err != nil {
		return generationPaths{}, err
	}
	generationDir, err := ops.mkdirTemp(generationsDir, "generation-")
	if err != nil {
		return generationPaths{}, fmt.Errorf("creating immutable certificate generation: %w", err)
	}
	if err := ops.syncDir(generationsDir); err != nil {
		cleanupErr := removeStagedGeneration(generationDir, ops)
		return generationPaths{}, errors.Join(
			fmt.Errorf("syncing new immutable certificate generation entry: %w", err),
			cleanupErr,
		)
	}
	if err := os.Chmod(generationDir, 0700); err != nil { //nolint:gosec // This is a directory; 0700 is the required private mode.
		cleanupErr := removeStagedGeneration(generationDir, ops)
		return generationPaths{}, errors.Join(
			fmt.Errorf("securing immutable certificate generation: %w", err),
			cleanupErr,
		)
	}

	result = generationPaths{
		Root:              root,
		Pointer:           filepath.Join(root, "current"),
		Directory:         generationDir,
		PreviousDirectory: previousGeneration,
		KeyFile:           filepath.Join(root, "current", generationKeyName),
		CertFile:          filepath.Join(root, "current", generationCertName),
		MarkerFile:        filepath.Join(generationDir, generationMarker),
	}
	cleanupStaged := true
	defer func() {
		if !cleanupStaged {
			return
		}
		if cleanupErr := removeStagedGeneration(generationDir, ops); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	if err := ops.writeFile(filepath.Join(generationDir, generationKeyName), keyPEM, 0600); err != nil {
		return generationPaths{}, fmt.Errorf("writing staged private key: %w", err)
	}
	if err := ops.syncDir(generationDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing staged private-key entry: %w", err)
	}
	if err := ops.writeFile(filepath.Join(generationDir, generationCertName), certPEM, 0644); err != nil {
		return generationPaths{}, fmt.Errorf("writing staged certificate: %w", err)
	}
	if err := ops.syncDir(generationDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing staged certificate entry: %w", err)
	}
	marker, err := json.Marshal(publicationMarker{
		CreatedAt:          time.Now().UTC(),
		PreviousGeneration: previousGeneration,
		Generation:         result.Directory,
		GenerationPointer:  result.Pointer,
		KeyFile:            result.KeyFile,
		CertFile:           result.CertFile,
	})
	if err != nil {
		return generationPaths{}, fmt.Errorf("marshalling generation publication marker: %w", err)
	}
	markerTemp := filepath.Join(generationDir, generationMarkerTemp)
	if err := ops.writeFile(markerTemp, marker, 0600); err != nil {
		return generationPaths{}, fmt.Errorf("writing generation publication marker: %w", err)
	}
	if err := ops.syncDir(generationDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing staged generation publication marker: %w", err)
	}
	if err := ops.rename(markerTemp, result.MarkerFile); err != nil {
		return generationPaths{}, fmt.Errorf("publishing generation publication marker: %w", err)
	}
	if err := ops.syncDir(generationDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing generation publication marker: %w", err)
	}

	relativeTarget, err := filepath.Rel(root, generationDir)
	if err != nil {
		return generationPaths{}, fmt.Errorf("building relative generation pointer: %w", err)
	}
	pointerTemp, err := createTemporaryGenerationPointer(root, relativeTarget, ops)
	if err != nil {
		return generationPaths{}, err
	}
	defer func() {
		if removeErr := removePathAndSync(pointerTemp, ops); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("removing temporary generation pointer %s: %w", pointerTemp, removeErr))
		}
	}()
	if err := ops.rename(pointerTemp, result.Pointer); err != nil {
		return generationPaths{}, fmt.Errorf("publishing certificate generation pointer: %w", err)
	}
	result.Switched = true
	cleanupStaged = false
	if err := ops.syncDir(root); err != nil {
		publishErr := fmt.Errorf("syncing published certificate generation pointer: %w", err)
		if rollbackErr := rollbackGenerationPublication(result, ops); rollbackErr != nil {
			return result, errors.Join(publishErr, fmt.Errorf("rolling back uncertain generation pointer: %w", rollbackErr))
		}
		return result, publishErr
	}
	return result, nil
}

func (ops generationPublishOps) complete() bool {
	return ops.writeFile != nil && ops.syncDir != nil && ops.symlink != nil &&
		ops.rename != nil && ops.remove != nil && ops.mkdirTemp != nil
}

func inspectGenerationPointer(root string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspecting certificate generation root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("certificate generation root %s is not a regular directory", root)
	}
	generationsPath := filepath.Join(root, "generations")
	generationsInfo, err := os.Lstat(generationsPath)
	if err != nil {
		return "", fmt.Errorf("inspecting certificate generations directory: %w", err)
	}
	if !generationsInfo.IsDir() || generationsInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("certificate generations path %s is not a regular directory", generationsPath)
	}
	pointer := filepath.Join(root, "current")
	info, err := os.Lstat(pointer)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspecting existing certificate generation pointer: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("refusing to replace non-symlink certificate generation pointer %s", pointer)
	}
	target, err := os.Readlink(pointer)
	if err != nil {
		return "", fmt.Errorf("reading existing certificate generation pointer: %w", err)
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(root, resolved)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	generations, err := filepath.Abs(generationsPath)
	if err != nil {
		return "", err
	}
	if !pathWithin(generations, resolved) || filepath.Clean(resolved) == filepath.Clean(generations) {
		return "", fmt.Errorf("existing certificate generation pointer resolves outside %s", generations)
	}
	targetInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspecting existing certificate generation: %w", err)
	}
	if !targetInfo.IsDir() || targetInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("existing certificate generation is not a regular directory")
	}
	return resolved, nil
}

func createTemporaryGenerationPointer(root, relativeTarget string, ops generationPublishOps) (string, error) {
	for range 32 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", fmt.Errorf("generating temporary generation pointer name: %w", err)
		}
		path := filepath.Join(root, ".current.tmp."+hex.EncodeToString(random))
		if err := ops.symlink(relativeTarget, path); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("creating temporary generation pointer: %w", err)
		}
		if err := ops.syncDir(root); err != nil {
			cleanupErr := removePathAndSync(path, ops)
			return "", errors.Join(
				fmt.Errorf("syncing temporary generation pointer: %w", err),
				cleanupErr,
			)
		}
		return path, nil
	}
	return "", fmt.Errorf("could not allocate a unique temporary generation pointer")
}

func writeExclusiveSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	closeWith := func(cause error) error {
		if closeErr := file.Close(); closeErr != nil {
			return errors.Join(cause, closeErr)
		}
		return cause
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return closeWith(err)
	}
	if _, err := file.Write(data); err != nil {
		return closeWith(err)
	}
	if err := file.Chmod(mode); err != nil {
		return closeWith(err)
	}
	if err := file.Sync(); err != nil {
		return closeWith(err)
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ensurePrivateDirectory(path string) error {
	return ensurePrivateDirectoryWithSync(path, syncDirectory)
}

func ensurePrivateDirectoryWithSync(path string, syncDir func(string) error) error {
	if err := mkdirAllWithoutSymlinksWithSync(path, 0700, syncDir); err != nil {
		return fmt.Errorf("creating private certificate directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private certificate path %s is not a regular directory", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private certificate directory %s has insecure mode %04o", path, info.Mode().Perm())
	}
	return nil
}

func mkdirAllWithoutSymlinks(path string, mode os.FileMode) error {
	return mkdirAllWithoutSymlinksWithSync(path, mode, syncDirectory)
}

func mkdirAllWithoutSymlinksWithSync(path string, mode os.FileMode, syncDir func(string) error) error {
	if syncDir == nil {
		return fmt.Errorf("directory sync operation is unavailable")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular directory", clean)
		}
		if err := validateDirectoryComponents(clean); err != nil {
			return err
		}
		parent := filepath.Dir(clean)
		if parent != clean {
			return syncDir(parent)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(clean)
	if parent == clean {
		return err
	}
	if err := mkdirAllWithoutSymlinksWithSync(parent, mode, syncDir); err != nil {
		return err
	}
	created := false
	if err := os.Mkdir(clean, mode); err != nil {
		if !os.IsExist(err) {
			return err
		}
		if err := syncDir(parent); err != nil {
			return err
		}
	} else {
		created = true
	}
	if created {
		if err := syncDir(parent); err != nil {
			return err
		}
	}
	info, err = os.Lstat(clean)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular directory", clean)
	}
	return nil
}

func validateDirectoryComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, current)
	if relative == "" {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular directory", current)
		}
	}
	return nil
}

func removePathAndSync(path string, ops generationPublishOps) error {
	err := ops.remove(path)
	if os.IsNotExist(err) {
		parent := filepath.Dir(path)
		if _, statErr := os.Lstat(parent); statErr == nil {
			return ops.syncDir(parent)
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		return nil
	}
	if err != nil {
		return err
	}
	return ops.syncDir(filepath.Dir(path))
}

func removeStagedGeneration(directory string, ops generationPublishOps) error {
	var errs []error
	for _, name := range []string{generationMarker, generationMarkerTemp, generationCertName, generationKeyName} {
		path := filepath.Join(directory, name)
		if err := removePathAndSync(path, ops); err != nil {
			errs = append(errs, fmt.Errorf("removing staged generation path %s: %w", path, err))
		}
	}
	if err := removePathAndSync(directory, ops); err != nil {
		errs = append(errs, fmt.Errorf("removing staged generation directory %s: %w", directory, err))
	}
	return errors.Join(errs...)
}

func finalizeGenerationPublication(paths generationPaths) error {
	return finalizeGenerationPublicationWithOps(paths, defaultGenerationPublishOps())
}

func finalizeGenerationPublicationWithOps(paths generationPaths, ops generationPublishOps) error {
	if paths.MarkerFile == "" {
		return nil
	}
	if err := ops.remove(paths.MarkerFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing committed generation marker %s: %w", paths.MarkerFile, err)
	}
	if paths.Directory != "" {
		if err := ops.syncDir(paths.Directory); err != nil {
			return fmt.Errorf("syncing committed generation directory: %w", err)
		}
	}
	return nil
}

func rollbackGenerationPublication(paths generationPaths, ops generationPublishOps) error {
	if paths.Root == "" || paths.Pointer == "" {
		return fmt.Errorf("generation rollback paths are incomplete")
	}
	return selectGenerationPointer(paths.Root, paths.PreviousDirectory, ops)
}

func selectGenerationPointer(root, desired string, ops generationPublishOps) (err error) {
	if !ops.complete() {
		return fmt.Errorf("certificate generation publisher is incomplete")
	}
	current, err := inspectGenerationPointer(root)
	if err != nil {
		return err
	}
	if desired != "" {
		if err := validateGenerationDirectory(root, desired); err != nil {
			return fmt.Errorf("validating generation rollback target: %w", err)
		}
	}
	if filepath.Clean(current) == filepath.Clean(desired) {
		return ops.syncDir(root)
	}
	pointer := filepath.Join(root, "current")
	if desired == "" {
		if current == "" {
			return ops.syncDir(root)
		}
		if err := ops.remove(pointer); err != nil {
			return fmt.Errorf("removing generation pointer during rollback: %w", err)
		}
		return ops.syncDir(root)
	}
	relativeTarget, err := filepath.Rel(root, desired)
	if err != nil {
		return err
	}
	temp, err := createTemporaryGenerationPointer(root, relativeTarget, ops)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := removePathAndSync(temp, ops); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("removing rollback pointer %s: %w", temp, removeErr))
		}
	}()
	if err := ops.rename(temp, pointer); err != nil {
		return fmt.Errorf("restoring generation pointer: %w", err)
	}
	if err := ops.syncDir(root); err != nil {
		return fmt.Errorf("syncing restored generation pointer: %w", err)
	}
	return nil
}

func validateGenerationDirectory(root, directory string) error {
	generations := filepath.Join(root, "generations")
	directoryAbs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	generationsAbs, err := filepath.Abs(generations)
	if err != nil {
		return err
	}
	if !pathWithin(generationsAbs, directoryAbs) || filepath.Clean(directoryAbs) == filepath.Clean(generationsAbs) {
		return fmt.Errorf("generation %s is outside %s", directory, generations)
	}
	info, err := os.Lstat(directoryAbs)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generation %s is not a regular directory", directory)
	}
	for _, name := range []string{generationKeyName, generationCertName} {
		path := filepath.Join(directoryAbs, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("generation artifact %s is not a regular file", path)
		}
	}
	return nil
}

func pathWithin(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
