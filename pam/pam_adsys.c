/*
 * This pam module sets DCONF_PROFILE for the user and updates its group
 * policy.
 *
 *
 * Copyright (C) 2021 Canonical
 *
 * Authors:
 *  Jean-Baptiste Lallement <jean-baptiste@ubuntu.com>
 *  Didier Roche <didrocks@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#ifndef ADSYS_POLICIES_DIR
#define ADSYS_POLICIES_DIR "/var/cache/adsys/policies/%s"
#endif

#ifndef ADSYS_DCONF_PROFILE_DIR
#define ADSYS_DCONF_PROFILE_DIR "/etc/dconf/profile"
#endif

#ifndef ADSYSCTL_PATH
#define ADSYSCTL_PATH "/sbin/adsysctl"
#endif

#ifndef ADSYS_GDM_GREETER_GROUP
#define ADSYS_GDM_GREETER_GROUP "gdm"
#endif

#ifndef ADSYS_DEBIAN_GDM_GREETER_GROUP
#define ADSYS_DEBIAN_GDM_GREETER_GROUP "Debian-gdm"
#endif

/*
 * Refresh the group policies of current user
 */
static int update_policy(pam_handle_t* pamh, const char* username, const char* krb5ccname, char** normalized_target,
                         int debug) {
    int retval = pam_info(pamh, "Applying user settings");
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    *normalized_target = NULL;
    if (memcmp(krb5ccname, (const char*)"FILE:", 5) == 0) {
        krb5ccname += 5;
    }

    char** arggv = calloc(7, sizeof(char*));
    if (arggv == NULL) {
        return PAM_BUF_ERR;
    }

    arggv[0] = ADSYSCTL_PATH;
    arggv[1] = "update";
    arggv[2] = "--print-normalized-target";
    arggv[3] = (char*)(username);
    arggv[4] = (char*)(krb5ccname);
    arggv[5] = NULL;
    if (debug) {
        arggv[5] = "-vv";
        arggv[6] = NULL;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        pam_syslog(pamh, LOG_ERR, "Failed to create pipe: %m");
        free(arggv);
        return PAM_SYSTEM_ERR;
    }

    pid_t pid = fork();
    if (pid == -1) {
        pam_syslog(pamh, LOG_ERR, "Failed to fork process");
        close(pipefd[0]);
        close(pipefd[1]);
        free(arggv);
        return PAM_SYSTEM_ERR;
    }

    if (pid > 0) { /* parent */
        close(pipefd[1]);
        char target_buffer[PATH_MAX];
        size_t target_length = 0;
        bool invalid_target = false;
        ssize_t n = 0;
        for (;;) {
            n = read(pipefd[0], target_buffer + target_length, sizeof(target_buffer) - target_length);
            if (n == -1 && errno == EINTR) {
                continue;
            }
            if (n <= 0) {
                break;
            }
            target_length += (size_t)n;
            if (target_length == sizeof(target_buffer)) {
                invalid_target = true;
                break;
            }
        }
        close(pipefd[0]);

        pid_t retval;
        int status = 0;

        while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR) {
        };

        if (retval == (pid_t)-1) {
            pam_syslog(pamh, LOG_ERR, "waitpid returns with -1: %m");
            free(arggv);
            return PAM_SYSTEM_ERR;
        } else if (status != 0) {
            if (WIFEXITED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl update %s %s failed: exit code %d", username, krb5ccname,
                           WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl update %s %s failed: caught signal %d%s", username, krb5ccname,
                           WTERMSIG(status), WCOREDUMP(status) ? " (core dumped)" : "");
            } else {
                pam_syslog(pamh, LOG_ERR, "adsysctl update %s %s failed: unknown status 0x%x", username, krb5ccname,
                           status);
            }
            free(arggv);
            return PAM_CRED_ERR;
        }

        if (n == -1 || invalid_target) {
            pam_syslog(pamh, LOG_ERR, "Failed to read normalized target from adsysctl");
            free(arggv);
            return PAM_SYSTEM_ERR;
        }

        if (target_length == 0 || target_buffer[target_length - 1] != '\n') {
            pam_syslog(pamh, LOG_WARNING,
                       "adsysctl did not return a valid normalized target; leaving DCONF_PROFILE unset");
            free(arggv);
            return PAM_SUCCESS;
        }
        target_length--;
        if (target_length == 0 || memchr(target_buffer, '\0', target_length) != NULL ||
            memchr(target_buffer, '\n', target_length) != NULL) {
            pam_syslog(pamh, LOG_WARNING,
                       "adsysctl did not return a valid normalized target; leaving DCONF_PROFILE unset");
            free(arggv);
            return PAM_SUCCESS;
        }
        *normalized_target = strndup(target_buffer, target_length);
        if (*normalized_target == NULL) {
            pam_syslog(pamh, LOG_CRIT, "out of memory");
            free(arggv);
            return PAM_BUF_ERR;
        }
        free(arggv);
        return PAM_SUCCESS;

    } else { /* child */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            pam_syslog(pamh, LOG_ERR, "Failed to redirect adsysctl output: %m");
            _exit(errno);
        }
        close(pipefd[1]);
        if (debug) {
            pam_syslog(pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);
        }

        execv(arggv[0], arggv);
        int i = errno;
        pam_syslog(pamh, LOG_ERR, "execv(%s,...) failed: %m", arggv[0]);
        free(arggv);
        _exit(i);
    }

    return PAM_SYSTEM_ERR; /* will never be reached. */
}

/*
 * Refresh the group policies of machine
 */
static int update_machine_policy(pam_handle_t* pamh, int debug) {
    int retval;
    retval = pam_info(pamh, "Applying machine settings");
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    char** arggv;
    arggv = calloc(5, sizeof(char*));
    if (arggv == NULL) {
        return PAM_BUF_ERR;
    }

    arggv[0] = ADSYSCTL_PATH;
    arggv[1] = "update";
    arggv[2] = "-m";
    arggv[4] = NULL;
    if (debug) {
        arggv[3] = "-vv";
        arggv[4] = NULL;
    }

    pid_t pid = fork();
    if (pid == -1) {
        pam_syslog(pamh, LOG_ERR, "Failed to fork process");
        return PAM_SYSTEM_ERR;
    }

    if (pid > 0) { /* parent */
        pid_t retval;
        int status = 0;

        while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR) {
        };

        if (retval == (pid_t)-1) {
            pam_syslog(pamh, LOG_ERR, "waitpid returns with -1: %m");
            free(arggv);
            return PAM_SYSTEM_ERR;
        } else if (status != 0) {
            if (WIFEXITED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl update -m failed: exit code %d", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl update -m failed: caught signal %d%s", WTERMSIG(status),
                           WCOREDUMP(status) ? " (core dumped)" : "");
            } else {
                pam_syslog(pamh, LOG_ERR, "adsysctl update -m failed: unknown status 0x%x", status);
            }
            free(arggv);
            return PAM_CRED_ERR;
        }
        free(arggv);
        return PAM_SUCCESS;

    } else { /* child */
        if (debug) {
            pam_syslog(pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);
        }

        execv(arggv[0], arggv);
        int i = errno;
        pam_syslog(pamh, LOG_ERR, "execv(%s,...) failed: %m", arggv[0]);
        free(arggv);
        _exit(i);
    }

    return PAM_SYSTEM_ERR; /* will never be reached. */
}

/*
 * Report whether the session belongs to a GDM greeter account.
 *
 * GDM runs its greeter under a dedicated account whose name is not stable: it
 * is Debian-gdm or gdm depending on the build, and since the switch to dynamic
 * users it can carry an arbitrary suffix. The account is however always a
 * member of the greeter group, which is what we match on.
 */
static bool is_greeter_user(pam_handle_t* pamh, const char* username) {
    if (username == NULL) {
        return false;
    }

    return pam_modutil_user_in_group_nam_nam(pamh, username, ADSYS_GDM_GREETER_GROUP) == 1 ||
           pam_modutil_user_in_group_nam_nam(pamh, username, ADSYS_DEBIAN_GDM_GREETER_GROUP) == 1;
}

/*
 * Set DCONF_PROFILE only when ADSys has installed a usable profile for the user.
 */
static int set_dconf_profile(pam_handle_t* pamh, const char* profile_name) {
    if (strchr(profile_name, '/') != NULL || strcmp(profile_name, ".") == 0 || strcmp(profile_name, "..") == 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "Refusing unsafe ADSys dconf profile name %s; leaving DCONF_PROFILE unset (ADSys dconf policy is "
                   "not applied)",
                   profile_name);
        return PAM_SUCCESS;
    }

    char* profile_path = NULL;
    if (asprintf(&profile_path, "%s/%s", ADSYS_DCONF_PROFILE_DIR, profile_name) < 0) {
        pam_syslog(pamh, LOG_CRIT, "out of memory");
        return PAM_BUF_ERR;
    }

    struct stat profile_status;
    if (stat(profile_path, &profile_status) != 0 || !S_ISREG(profile_status.st_mode)) {
        pam_syslog(pamh, LOG_WARNING,
                   "ADSys dconf profile %s was not found as a regular file; leaving DCONF_PROFILE unset (ADSys dconf "
                   "policy is not applied)",
                   profile_name);
        free(profile_path);
        return PAM_SUCCESS;
    }
    free(profile_path);

    char* envvar;
    if (asprintf(&envvar, "DCONF_PROFILE=%s", profile_name) < 0) {
        pam_syslog(pamh, LOG_CRIT, "out of memory");
        return PAM_BUF_ERR;
    }

    int retval = pam_putenv(pamh, envvar);
    _pam_drop(envvar);
    return retval;
}

/*
 * Get the ticket path for the user by calling adsysctl policy debug ticket-path
 */
static int get_krb5cc_ticket_path(pam_handle_t* pamh, const char* username, char** path) {
    char** arggv;
    arggv = calloc(6, sizeof(char*));
    if (arggv == NULL) {
        return 1;
    }

    arggv[0] = ADSYSCTL_PATH;
    arggv[1] = "policy";
    arggv[2] = "debug";
    arggv[3] = "ticket-path";
    arggv[4] = (char*)(username);
    arggv[5] = NULL;

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        pam_syslog(pamh, LOG_ERR, "Failed to create pipe: %m");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        pam_syslog(pamh, LOG_ERR, "Failed to fork process");
        return 1;
    }

    if (pid > 0) { /* parent */
        pid_t retval;
        int status = 0;

        while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR) {
        };

        if (retval == (pid_t)-1) {
            pam_syslog(pamh, LOG_ERR, "waitpid returns with -1: %m");
            free(arggv);
            return 1;
        } else if (status != 0) {
            if (WIFEXITED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl policy debug ticket-path %s failed: exit code %d", username,
                           WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                pam_syslog(pamh, LOG_ERR, "adsysctl policy debug ticket-path %s failed: caught signal %d%s", username,
                           WTERMSIG(status), WCOREDUMP(status) ? " (core dumped)" : "");
            } else {
                pam_syslog(pamh, LOG_ERR, "adsysctl policy debug ticket-path %s failed: unknown status 0x%x", username,
                           status);
            }
            free(arggv);
            return 1;
        }
        free(arggv);
        close(pipefd[1]);

        char ticket_path[PATH_MAX + 1];
        ssize_t n;
        while ((n = read(pipefd[0], ticket_path, sizeof(ticket_path))) > 0) {
            if (n == -1) {
                pam_syslog(pamh, LOG_ERR, "Failed to read from pipe: %m");
                return 1;
            }
            ticket_path[n] = '\0';
            char* newline = strchr(ticket_path, '\n');
            if (newline != NULL) {
                *newline = '\0';
            }
            close(pipefd[0]);
            *path = strdup(ticket_path);
            return 0;
        }
    } else { /* child */
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(arggv[0], arggv);
        int i = errno;
        pam_syslog(pamh, LOG_ERR, "execv(%s,...) failed: %m", arggv[0]);
        free(arggv);
        _exit(i);
    }

    return 0; /* command had no output and exited with 0 */
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) { return PAM_IGNORE; }

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) { return PAM_IGNORE; }

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    int retval = PAM_SUCCESS;

    int debug = 0;
    int optargc;

    for (optargc = 0; optargc < argc; optargc++) {
        if (strcasecmp(argv[optargc], "debug") == 0) {
            debug = 1;
        } else {
            break; /* Unknown option. */
        }
    }

    const char* username;
    if (pam_get_item(pamh, PAM_USER, (void*)&username) != PAM_SUCCESS) {
        D(("pam_get_item failed for PAM_USER"));
        return PAM_SYSTEM_ERR; /* let pam_get_item() log the error */
    }

    /*
      Greeter sessions are entirely driven by the machine GPO: there is no
      Kerberos ticket to locate, no user policy to refresh, and GDM exports the
      dconf profile it was built against on its own.
    */
    if (is_greeter_user(pamh, username)) {
        return PAM_IGNORE;
    }

    /*
     * We consider that KRB5CCNAME is always set by SSSD for remote users
     */
    const char* krb5ccname = pam_getenv(pamh, "KRB5CCNAME");
    if (krb5ccname == NULL) {
        char* ticket_path = NULL;

        // An error here means the detect_cached_ticket setting is enabled
        if (get_krb5cc_ticket_path(pamh, username, &ticket_path) != 0) {
            pam_syslog(pamh, LOG_ERR, "Failed to get ticket path for user %s", username);
            return PAM_SYSTEM_ERR;
        };

        // The detect_cached_ticket setting is disabled or we weren't able to
        // locate a the path returned by krb5 on disk
        if (ticket_path == NULL || *ticket_path == '\0') {
            return PAM_IGNORE;
        }

        // We have a ticket, proceed with setting the environment variable
        char* envvar;
        if (asprintf(&envvar, "KRB5CCNAME=FILE:%s", ticket_path) < 0) {
            pam_syslog(pamh, LOG_CRIT, "out of memory");
            free(ticket_path);
            return PAM_BUF_ERR;
        }

        retval = pam_putenv(pamh, envvar);
        krb5ccname = strdup(ticket_path);
        _pam_drop(envvar);
        free(ticket_path);
        if (retval != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Failed to set KRB5CCNAME to %s", ticket_path);
            return PAM_SYSTEM_ERR;
        }
    }

    /*
      trying to update machine policy first if no machine gpo cache (meaning adsysd boot service failed due to being
      offline for instance)
    */
    char hostname[HOST_NAME_MAX + 1];
    char cache_path[HOST_NAME_MAX + 1 + strlen(ADSYS_POLICIES_DIR) - 2];
    if (gethostname(hostname, HOST_NAME_MAX + 1) < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to get hostname");
        return PAM_SYSTEM_ERR;
    }
    if (sprintf(cache_path, ADSYS_POLICIES_DIR, hostname) < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to allocate cache_path");
        return PAM_BUF_ERR;
    }
    if (access(cache_path, F_OK) != 0) {
        int r;
        r = update_machine_policy(pamh, debug);
        if (r != 0) {
            return r;
        }
    }

    char* profile_name = NULL;
    retval = update_policy(pamh, username, krb5ccname, &profile_name, debug);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    if (profile_name == NULL) {
        return PAM_SUCCESS;
    }

    retval = set_dconf_profile(pamh, profile_name);
    free(profile_name);
    return retval;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc, const char** argv) { return PAM_SUCCESS; }

/* end of module definition */
