package doc

import (
	"embed"
	"fmt"
	"path/filepath"
	"reflect"
)

// Dir is the embedded directory containing documentation
// Only embed structured documentation.
//go:embed *-*.md
var Dir embed.FS

// SplitFilesToken is the prefix between multiple documentation pages.
const SplitFilesToken = "----==----"

type foo struct{}

// GetPackageURL returns a distant link to a raw binary content related to this directory.
func GetPackageURL() string {
	return fmt.Sprintf("https://%s/raw/main/doc", filepath.Dir(reflect.TypeOf(foo{}).PkgPath()))
}
