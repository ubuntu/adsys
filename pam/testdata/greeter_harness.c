#include "pam_adsys.c"

static const char* test_username;
static const char* test_group;

int pam_modutil_user_in_group_nam_nam(pam_handle_t* pamh, const char* user, const char* group) {
    (void)pamh;
    return strcmp(user, test_username) == 0 && strcmp(group, test_group) == 0;
}

int pam_get_item(const pam_handle_t* pamh, int item_type, const void** item) {
    (void)pamh;
    if (item_type != PAM_USER) {
        abort();
    }
    *item = test_username;
    return PAM_SUCCESS;
}

const char* pam_getenv(pam_handle_t* pamh, const char* name) {
    (void)pamh;
    (void)name;
    /* Greeters must return before looking for a ticket or changing dconf. */
    abort();
}

int main(int argc, char** argv) {
    if (argc != 3) {
        return 2;
    }
    test_username = argv[1];
    test_group = argv[2];

    bool greeter = is_greeter_user(NULL, test_username);
    if (greeter && pam_sm_open_session(NULL, 0, 0, NULL) != PAM_IGNORE) {
        return 3;
    }
    printf("%d\n", greeter);
    return 0;
}
