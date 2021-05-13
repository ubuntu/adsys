package doc

import (
	"embed"
	"fmt"
	"path/filepath"
	"reflect"
)

//go:embed *.md
// Dir is the embedded directory containing documentation
var Dir embed.FS

type foo struct{}

// GetPackageURL returns a distant link to a raw binary content related to this directory
func GetPackageURL() string {
	return fmt.Sprintf("https://%s/raw/main/doc", filepath.Dir(reflect.TypeOf(foo{}).PkgPath()))
}
