#include "libkrb5_mock.h"

#include <krb5.h>
#include <stdio.h>
#include <string.h>

char *get_krb5_mock_behavior() { return getenv("ADSYS_KRB5_BEHAVIOR"); }

const char *KRB5_CALLCONV krb5_cc_default_name(krb5_context context) {
    char *behavior = get_krb5_mock_behavior();
    if (behavior == NULL) {
        printf("ADSYS_KRB5_BEHAVIOR not set, returning dummy value...");
        return "FILE:/tmp/krb5cc_0";
    }

    if (strcmp(behavior, "return_empty_ccache") == 0) {
        return "";
    }
    if (strcmp(behavior, "return_null_ccache") == 0) {
        return NULL;
    }
    if (strstr(behavior, "return_ccache") != NULL) {
        // split the string by the first colon
        char *ccname = strtok(behavior, ":");
        ccname = strtok(NULL, "");
        return ccname;
    }
    if (strstr(behavior, "return_memory_ccache") != NULL) {
        return "MEMORY:foo";
    }

    printf("Unknown behavior: %s", behavior);
    exit(1);
}
