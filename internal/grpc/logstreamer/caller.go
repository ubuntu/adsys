package log

import (
	"runtime"
	"strings"
	"sync"
)

// This is taken from logrus

var (
	// qualified package name, cached at first use.
	thisPackage string

	// Positions in the call stack when tracing to report the calling method.
	minimumCallerDepth int

	// Used for caller information initialisation.
	callerInitOnce sync.Once
)

const (
	maximumCallerDepth  int = 25
	knownInternalFrames int = 2
)

// getCaller retrieves the name of the first non-logrus calling function.
func getCaller() *runtime.Frame {
	// cache this package's fully-qualified name
	getPackageFunc := func() {
		pcs := make([]uintptr, maximumCallerDepth)
		_ = runtime.Callers(0, pcs)

		// dynamic get the package name and the minimum caller depth
		for i := 0; i < maximumCallerDepth; i++ {
			funcName := runtime.FuncForPC(pcs[i]).Name()
			if strings.Contains(funcName, "getCaller") {
				thisPackage = getPackageName(funcName)
				break
			}
		}

		minimumCallerDepth = knownInternalFrames
	}
	callerInitOnce.Do(getPackageFunc)

	// Restrict the lookback frames to avoid runaway lookups
	pcs := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(minimumCallerDepth, pcs)
	frames := runtime.CallersFrames(pcs[:depth])

	for f, again := frames.Next(); again; f, again = frames.Next() {
		pkg := getPackageName(f.Function)

		// If the caller isn't part of this package, we're done
		if pkg != thisPackage {
			return &f //nolint:scopelint
		}
	}

	// if we got here, we failed to find the caller's context
	return nil
}

// getPackageName reduces a fully qualified function name to the package name
// There really ought to be to be a better way...
func getPackageName(f string) string {
	for {
		lastPeriod := strings.LastIndex(f, ".")
		lastSlash := strings.LastIndex(f, "/")
		if lastPeriod > lastSlash {
			f = f[:lastPeriod]
		} else {
			break
		}
	}

	return f
}
