// TiCS: disabled // This is a kerberos C library that we are mocking for testing purposes.

#include <krb5.h>
#include <stdio.h>
#include <string.h>

#include "libkrb5_mock.h"

krb5_error_code KRB5_CALLCONV krb5_init_context(krb5_context* context) {
    char* behavior = get_krb5_mock_behavior();
    if (strcmp(behavior, "error_initializing_context") == 0) {
        return KRB5KRB_ERR_GENERIC;
    }

    return 0;
}
