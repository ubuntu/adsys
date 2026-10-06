#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <stdio.h>
#include <stdlib.h>

int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv);

int pam_modutil_user_in_group_nam_nam(pam_handle_t* pamh, const char* user, const char* group) {
    (void)pamh;
    (void)user;
    (void)group;
    return 0;
}

static int conversation(int num_msg, const struct pam_message** messages, struct pam_response** responses,
                        void* appdata_ptr) {
    (void)messages;
    (void)appdata_ptr;

    if (num_msg < 0) {
        return PAM_CONV_ERR;
    }

    *responses = calloc((size_t)num_msg, sizeof(**responses));
    if (num_msg > 0 && *responses == NULL) {
        return PAM_BUF_ERR;
    }
    return PAM_SUCCESS;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }

    const char* ccache_env = getenv("ADSYS_TEST_KRB5CCNAME");
    if (ccache_env == NULL) {
        return 3;
    }

    struct pam_conv conv = {conversation, NULL};
    pam_handle_t* pamh = NULL;
    int retval = pam_start("adsys-test", argv[1], &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        return 4;
    }

    retval = pam_putenv(pamh, ccache_env);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 5;
    }

    retval = pam_sm_open_session(pamh, 0, 0, NULL);
    printf("pam_return=%d\n", retval);

    const char* profile = pam_getenv(pamh, "DCONF_PROFILE");
    printf("dconf_profile=%s\n", profile == NULL ? "<unset>" : profile);

    pam_end(pamh, retval);
    return 0;
}
