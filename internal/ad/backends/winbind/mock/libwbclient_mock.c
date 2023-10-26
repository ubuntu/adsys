#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wbclient.h>

char *get_mock_behavior() {
    char *behavior = getenv("ADSYS_WBCLIENT_BEHAVIOR");
    if (behavior == NULL) {
        printf("ADSYS_WBCLIENT_BEHAVIOR not set, exiting...");
        exit(1);
    }
    return behavior;
}

wbcErr wbcLookupDomainController(const char *domain, uint32_t flags, struct wbcDomainControllerInfo **dc_info) {
    char *behavior = get_mock_behavior();
    if (strcmp(behavior, "error_getting_dc_name") == 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    struct wbcDomainControllerInfo *dc = malloc(sizeof(struct wbcDomainControllerInfo));
    // This is the only field used at the moment
    dc->dc_name = "\\\\adcontroller.example.com";

    // For integration tests, we need to use the URL to the local SMB server as
    // we will need to download files from it
    if (strcmp(behavior, "integration_tests") == 0) {
        dc->dc_name = "\\\\localhost:1446";
    }
    *dc_info = dc;
    return WBC_ERR_SUCCESS;
}

wbcErr wbcInterfaceDetails(struct wbcInterfaceDetails **details) {
    char *behavior = get_mock_behavior();
    if (strcmp(behavior, "domain_not_found") == 0) {
        return WBC_ERR_DOMAIN_NOT_FOUND;
    }

    struct wbcInterfaceDetails *info = malloc(sizeof(struct wbcInterfaceDetails));
    // This is the only field used at the moment
    info->dns_domain = "example.com";
    *details = info;
    return WBC_ERR_SUCCESS;
}

wbcErr wbcDomainInfo(const char *domain, struct wbcDomainInfo **dinfo) {
    char *behavior = get_mock_behavior();
    if (strcmp(behavior, "error_getting_online_status") == 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    struct wbcDomainInfo *info = malloc(sizeof(struct wbcDomainInfo));
    info->domain_flags = WBC_DOMINFO_DOMAIN_PRIMARY;
    if (strcmp(behavior, "domain_is_offline") == 0) {
        info->domain_flags |= WBC_DOMINFO_DOMAIN_OFFLINE;
    }
    *dinfo = info;
    return WBC_ERR_SUCCESS;
}
