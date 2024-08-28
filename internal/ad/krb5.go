package ad

/*
#include <errno.h>
#include <string.h>

#include <krb5.h>

char *get_ticket_path() {
  krb5_error_code ret;
  krb5_context context;

  ret = krb5_init_context(&context);
  if (ret) {
    errno = ret;
    return NULL;
  }
  // We need to reset the errno to 0, because krb5_init_context()
  // can alter it,  even if it succeeds.
  errno = 0;

  const char* cc_name = krb5_cc_default_name(context);
  if (cc_name == NULL) {
    return NULL;
  }

  return strdup(cc_name);
}
*/
// #cgo pkg-config: krb5
import "C"

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/leonelquinteros/gotext"
)

// ErrTicketNotPresent is returned when the ticket cache is not present or not accessible
var ErrTicketNotPresent = errors.New(gotext.Get("ticket not found or not accessible"))

// TicketPath returns the path of the default kerberos ticket cache for the
// current user.
// It returns an error if the path is empty or does not exist on the disk.
func TicketPath() (string, error) {
	cKrb5cc, err := C.get_ticket_path()
	defer C.free(unsafe.Pointer(cKrb5cc))
	if err != nil {
		//nolint:govet,staticcheck // printf,SA1006: this is an i18n formatted const string
		return "", fmt.Errorf(gotext.Get("error initializing krb5 context, krb5_error_code: %d", err))
	}
	krb5cc := C.GoString(cKrb5cc)
	if krb5cc == "" {
		return "", errors.New(gotext.Get("path is empty"))
	}

	krb5ccPath := strings.TrimPrefix(krb5cc, "FILE:")
	fileInfo, err := os.Stat(krb5ccPath)
	if err != nil {
		return "", errors.Join(ErrTicketNotPresent, err)
	}
	if !fileInfo.Mode().IsRegular() {
		//nolint:govet,staticcheck // printf,SA1006: this is an i18n formatted const string
		return "", fmt.Errorf(gotext.Get("%q is not a regular file", krb5ccPath))
	}

	return krb5ccPath, nil
}
