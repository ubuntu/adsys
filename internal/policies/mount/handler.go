package mount

/*
#cgo pkg-config: glib-2.0 gio-2.0 gobject-2.0
#include <glib.h>
#include <gio/gio.h>

static inline void connect_signal(GMountOperation *op, char *signal, GCallback cb, gpointer data) {
	g_signal_connect(G_OBJECT(op), signal, cb, data);
}

static inline GCallback to_g_callback(void *f) {
	return G_CALLBACK(f);
}

static inline GAsyncReadyCallback to_g_async_ready_callback(void *f) {
	return (GAsyncReadyCallback)f;
}

static inline GFile* to_g_file(GObject *obj) {
	return G_FILE(obj);
}

extern void askPassword(GMountOperation*, char*, char*, char*, GAskPasswordFlags);
extern void mountDone(GObject*, GAsyncResult*, gpointer);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// mountEntry represents a parsed entry to be mounted.
type mountEntry struct {
	path    string
	krbAuth bool
}

// msg struct is the message structure that will be used to communicate in the mountsChan channel.
type msg struct {
	path string
	err  error
}

// mountsChan is the channel through which the async mount operations will communicate with the main
// routine.
// We need a global channel in order to communicate with the main routine from the callbacks, avoiding
// GIOChannel complexity.
// The callbacks in gio allow for additional data to passed as gpointers, but we can't use it to
// pass a channel pointer due to the CGo rules. It emitted the following error:
// "panic: runtime error: cgo argument has Go pointer to Go pointer".
var mountsChan chan msg

// RunMountForCurrentUser reads the specified file and tries to mount the parsed entries for the
// current user.
func RunMountForCurrentUser(ctx context.Context, filepath string) error {
	log.Debugf(ctx, "Reading mount entries from %q", filepath)
	entries, err := parseEntries(filepath)
	if err != nil || len(entries) == 0 {
		return err
	}

	mountsChan = make(chan msg, len(entries))

	for _, entry := range entries {
		cleanup := setupMountOperation(entry)
		// We need to defer the cleanup function in order to avoid memory leaks.
		defer cleanup()
	}
	mainLoop := C.g_main_loop_new(C.g_main_context_default(), C.FALSE)

	doneMain := make(chan struct{})
	go func() {
		C.g_main_loop_run(mainLoop)
		close(doneMain)
	}()

	// watches the mountsChan channel for the results of the mount operations.
	for range entries {
		m := <-mountsChan
		logMsg := fmt.Sprintf("Successfully mounted %q", m.path)
		if m.err != nil {
			logMsg = fmt.Sprintf("Failed to mount %q: %v", m.path, m.err)
			err = errors.Join(err, fmt.Errorf("failed to mount %q: %w", m.path, m.err))
		}
		log.Debug(ctx, logMsg)
	}

	C.g_main_loop_quit(mainLoop)
	<-doneMain

	C.g_main_loop_unref(mainLoop)
	return err
}

// parseEntries reads the specified file and parses the listed mount locations from it.
func parseEntries(filepath string) ([]mountEntry, error) {
	var entries []mountEntry

	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		line, krb := strings.CutPrefix(line, "[krb5]")
		entries = append(entries, mountEntry{path: line, krbAuth: krb})
	}

	return entries, nil
}

// setupMountOperation creates and starts a gio mount operation for the specified location.
// It returns a cleanup function to clean all the allocated C resources.
func setupMountOperation(entry mountEntry) func() {
	path := C.CString(entry.path)
	file := C.g_file_new_for_uri(path)

	op := C.g_mount_operation_new()

	var isAnonymous C.int = C.TRUE
	if entry.krbAuth {
		isAnonymous = C.FALSE
	}
	C.g_mount_operation_set_anonymous(op, isAnonymous)

	sig := C.CString("ask_password")
	C.connect_signal(op, sig, C.to_g_callback(C.askPassword), nil)

	C.g_file_mount_enclosing_volume(
		file,
		C.GMountMountFlags(0),
		op,
		C.g_cancellable_get_current(),
		C.to_g_async_ready_callback(C.mountDone),
		nil)

	return func() {
		C.g_object_unref(C.gpointer(file))
		C.g_object_unref(C.gpointer(op))
		C.free(unsafe.Pointer(path))
		C.free(unsafe.Pointer(sig))
	}
}

// askPassword is the callback function that will be called when the mount operation needs a password.
//
//export askPassword
//nolint:revive // We can't use _ for multiple unused parameters in exported functions.
func askPassword(op *C.GMountOperation, unused1, unused2, unused3 *C.char, flags C.GAskPasswordFlags) {
	rCode := C.GMountOperationResult(C.G_MOUNT_OPERATION_ABORTED)

	// Checks if the mount operation is anonymous and if the anonymous flag is supported.
	if C.g_mount_operation_get_anonymous(op) == C.TRUE {
		if flags&C.G_ASK_PASSWORD_ANONYMOUS_SUPPORTED == C.G_ASK_PASSWORD_ANONYMOUS_SUPPORTED {
			rCode = C.GMountOperationResult(C.G_MOUNT_OPERATION_HANDLED)
		}
	} else if os.Getenv("KRB5CCNAME") != "" {
		// Otherwise, checks if the kerberos ticket is available.
		rCode = C.GMountOperationResult(C.G_MOUNT_OPERATION_HANDLED)
	}
	C.g_mount_operation_reply(op, rCode)
}

// mountDone is the callback function that will be called when the mount operation is done.
//
//export mountDone
func mountDone(sourceObject *C.GObject, res *C.GAsyncResult, _ C.gpointer) {
	f := C.to_g_file(sourceObject)
	uri := C.g_file_get_uri(f)
	defer C.free(unsafe.Pointer(uri))

	var err *C.GError
	C.g_file_mount_enclosing_volume_finish(f, res, &err)

	doneMsg := msg{path: C.GoString(uri)}
	if err != nil {
		defer C.g_error_free(err)
		doneMsg.err = errors.New(C.GoString(err.message))
	}
	mountsChan <- doneMsg
}
