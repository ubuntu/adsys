package doc

import (
	"embed"
	"fmt"
	"path/filepath"
	"reflect"
)

//go:embed *.md
var Dir embed.FS

type foo struct{}

func GetPackageUrl() string {
	return fmt.Sprintf("https://%s/raw/main/doc", filepath.Dir(reflect.TypeOf(foo{}).PkgPath()))
}
