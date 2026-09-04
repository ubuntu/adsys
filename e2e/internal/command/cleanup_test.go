package command_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/scripts"
)

// TestActionCleanupObservesReturnedError guards the scenarios that dispose of
// remote resources when they fail.
//
// Those scenarios create Azure VMs and delete them again from a deferred
// closure that inspects err. If the enclosing action returns an unnamed error,
// that closure reads the local err variable rather than the value being
// returned, and the failure paths that bind their own err inside an if
// statement leave it untouched. Cleanup is then skipped without a word, which
// both leaks the VM and hides the error that caused it, as the closure is also
// what logs it.
//
// Naming the result is what ties the two together, so assert it statically:
// reproducing it otherwise would mean provisioning real infrastructure and
// then failing it on purpose.
func TestActionCleanupObservesReturnedError(t *testing.T) {
	rootDir, err := scripts.RootDir()
	require.NoError(t, err, "Setup: could not determine repository root directory")

	cmdDir := filepath.Join(rootDir, "e2e", "cmd")

	var checked int
	err = filepath.WalkDir(cmdDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !deferredClosureReadsErr(fn.Body) {
				continue
			}

			checked++
			rel, err := filepath.Rel(rootDir, path)
			require.NoError(t, err, "Setup: could not relativize %s", path)
			require.Truef(t, hasNamedErrResult(fn),
				"%s: %s defers cleanup that inspects err, so it must declare a named err result, "+
					"otherwise failures returned from an inner `if err := ...` leave that err nil and "+
					"the cleanup is silently skipped", rel, fn.Name.Name)
		}

		return nil
	})
	require.NoError(t, err, "Setup: could not walk the scenarios directory")
	require.NotZero(t, checked, "Setup: expected to find at least one action deferring cleanup on error")
}

// deferredClosureReadsErr reports whether body defers a closure that reads an
// err it did not declare itself, which is the shape used to clean up after a
// failed scenario.
func deferredClosureReadsErr(body *ast.BlockStmt) bool {
	var found bool

	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		deferStmt, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		closure, ok := deferStmt.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}

		// Only the outer err matters here: the cleanup routinely binds its own
		// err for the deletion call it makes, and that one says nothing about
		// whether the scenario failed.
		ast.Inspect(closure.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			if ifStmt, ok := n.(*ast.IfStmt); ok && ifStmt.Init != nil {
				if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok && assign.Tok == token.DEFINE {
					// Skip the whole statement: its err is a different one.
					return false
				}
			}
			if ident, ok := n.(*ast.Ident); ok && ident.Name == "err" {
				found = true
			}
			return true
		})

		return true
	})

	return found
}

// hasNamedErrResult reports whether fn declares its error result as err.
func hasNamedErrResult(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}

	for _, result := range fn.Type.Results.List {
		for _, name := range result.Names {
			if name.Name == "err" {
				return true
			}
		}
	}

	return false
}
