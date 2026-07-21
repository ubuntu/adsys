package certificate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	generationKeyName  = "private.key"
	generationCertName = "certificate.crt"
	generationMarker   = "publication.json"
)

type generationPaths struct {
	Root       string
	Pointer    string
	Directory  string
	KeyFile    string
	CertFile   string
	MarkerFile string
	Switched   bool
}

type generationPublishOps struct {
	writeFile func(string, []byte, os.FileMode) error
	syncDir   func(string) error
	symlink   func(string, string) error
	rename    func(string, string) error
}

func defaultGenerationPublishOps() generationPublishOps {
	return generationPublishOps{
		writeFile: writeExclusiveSyncedFile,
		syncDir:   syncDirectory,
		symlink:   os.Symlink,
		rename:    os.Rename,
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
// symlink. A non-empty result with an error means the pointer was switched and
// callers must still durably save state; the marker is deliberately retained
// for later reconciliation.
func publishCertificateGeneration(root string, keyPEM, certPEM []byte, ops generationPublishOps) (result generationPaths, err error) {
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return generationPaths{}, fmt.Errorf("refusing to publish an incomplete certificate generation")
	}
	if ops.writeFile == nil || ops.syncDir == nil || ops.symlink == nil || ops.rename == nil {
		return generationPaths{}, fmt.Errorf("certificate generation publisher is incomplete")
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return generationPaths{}, err
	}
	generationsDir := filepath.Join(root, "generations")
	if err := ensurePrivateDirectory(generationsDir); err != nil {
		return generationPaths{}, err
	}

	previousGeneration, err := inspectGenerationPointer(root)
	if err != nil {
		return generationPaths{}, err
	}
	generationDir, err := os.MkdirTemp(generationsDir, "generation-")
	if err != nil {
		return generationPaths{}, fmt.Errorf("creating immutable certificate generation: %w", err)
	}
	if err := os.Chmod(generationDir, 0700); err != nil { //nolint:gosec // This is a directory; 0700 is the required private mode.
		_ = os.Remove(generationDir)
		return generationPaths{}, fmt.Errorf("securing immutable certificate generation: %w", err)
	}

	result = generationPaths{
		Root:       root,
		Pointer:    filepath.Join(root, "current"),
		Directory:  generationDir,
		KeyFile:    filepath.Join(root, "current", generationKeyName),
		CertFile:   filepath.Join(root, "current", generationCertName),
		MarkerFile: filepath.Join(generationDir, generationMarker),
	}
	cleanupStaged := true
	defer func() {
		if !cleanupStaged {
			return
		}
		if cleanupErr := removeStagedGeneration(generationDir); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	if err := ops.writeFile(filepath.Join(generationDir, generationKeyName), keyPEM, 0600); err != nil {
		return generationPaths{}, fmt.Errorf("writing staged private key: %w", err)
	}
	if err := ops.writeFile(filepath.Join(generationDir, generationCertName), certPEM, 0644); err != nil {
		return generationPaths{}, fmt.Errorf("writing staged certificate: %w", err)
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
	if err := ops.writeFile(result.MarkerFile, marker, 0600); err != nil {
		return generationPaths{}, fmt.Errorf("writing generation publication marker: %w", err)
	}
	if err := ops.syncDir(generationDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing staged certificate generation: %w", err)
	}
	if err := ops.syncDir(generationsDir); err != nil {
		return generationPaths{}, fmt.Errorf("syncing certificate generations directory: %w", err)
	}

	pointerTemp, err := uniquePointerPath(root)
	if err != nil {
		return generationPaths{}, err
	}
	defer func() {
		if removeErr := os.Remove(pointerTemp); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, fmt.Errorf("removing temporary generation pointer %s: %w", pointerTemp, removeErr))
		}
	}()
	relativeTarget, err := filepath.Rel(root, generationDir)
	if err != nil {
		return generationPaths{}, fmt.Errorf("building relative generation pointer: %w", err)
	}
	if err := ops.symlink(relativeTarget, pointerTemp); err != nil {
		return generationPaths{}, fmt.Errorf("creating temporary generation pointer: %w", err)
	}
	if err := ops.syncDir(root); err != nil {
		return generationPaths{}, fmt.Errorf("syncing temporary generation pointer: %w", err)
	}
	if err := ops.rename(pointerTemp, result.Pointer); err != nil {
		return generationPaths{}, fmt.Errorf("publishing certificate generation pointer: %w", err)
	}
	result.Switched = true
	cleanupStaged = false
	if err := ops.syncDir(root); err != nil {
		return result, fmt.Errorf("syncing published certificate generation pointer: %w", err)
	}
	return result, nil
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

func uniquePointerPath(root string) (string, error) {
	file, err := os.CreateTemp(root, ".current.tmp.*")
	if err != nil {
		return "", fmt.Errorf("reserving temporary generation pointer: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
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
	if err := mkdirAllWithoutSymlinks(path, 0700); err != nil {
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
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular directory", clean)
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
	if err := mkdirAllWithoutSymlinks(parent, mode); err != nil {
		return err
	}
	if err := os.Mkdir(clean, mode); err != nil && !os.IsExist(err) {
		return err
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

func removeStagedGeneration(directory string) error {
	var errs []error
	for _, name := range []string{generationMarker, generationCertName, generationKeyName} {
		path := filepath.Join(directory, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing staged generation path %s: %w", path, err))
		}
	}
	if err := os.Remove(directory); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing staged generation directory %s: %w", directory, err))
	}
	return errors.Join(errs...)
}

func finalizeGenerationPublication(paths generationPaths) error {
	if paths.MarkerFile == "" {
		return nil
	}
	if err := os.Remove(paths.MarkerFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing committed generation marker %s: %w", paths.MarkerFile, err)
	}
	if paths.Directory != "" {
		if err := syncDirectory(paths.Directory); err != nil {
			return fmt.Errorf("syncing committed generation directory: %w", err)
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
