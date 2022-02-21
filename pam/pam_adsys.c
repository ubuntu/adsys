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
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

#define ADSYS_POLICIES_DIR "/var/cache/adsys/policies/%s"

/*
 * Refresh the group policies of current user
 */
static int update_policy(pam_handle_t * pamh, const char *username, const char *krb5ccname, int debug)
{
	int retval;
	retval = pam_info(pamh, "Applying user settings");
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (memcmp(krb5ccname, (const char *)"FILE:", 5) == 0) {
		krb5ccname += 5;
	}

	char **arggv;
	arggv = calloc(6, sizeof(char *));
	if (arggv == NULL) {
		return PAM_BUF_ERR;
	}

	arggv[0] = "/sbin/adsysctl";
	arggv[1] = "update";
	arggv[2] = (char *)(username);
	arggv[3] = (char *)(krb5ccname);
	arggv[4] = NULL;
	if (debug) {
		arggv[4] = "-vv";
		arggv[5] = NULL;
	}

	pid_t pid = fork();
	if (pid == -1) {
		pam_syslog(pamh, LOG_ERR, "Failed to fork process");
		return PAM_SYSTEM_ERR;
	}

	if (pid > 0) {		/* parent */
		pid_t retval;
		int status = 0;

		while ((retval = waitpid(pid, &status, 0)) == -1
		       && errno == EINTR) ;

		if (retval == (pid_t) - 1) {
			pam_syslog(pamh, LOG_ERR,
				   "waitpid returns with -1: %m");
			free(arggv);
			return PAM_SYSTEM_ERR;
		} else if (status != 0) {
			if (WIFEXITED(status)) {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update %s %s failed: exit code %d",
					   username, krb5ccname,
					   WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update %s %s failed: caught signal %d%s",
					   username, krb5ccname,
					   WTERMSIG(status),
					   WCOREDUMP(status) ? " (core dumped)"
					   : "");
			} else {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update %s %s failed: unknown status 0x%x",
					   username, krb5ccname, status);
			}
			free(arggv);
			return PAM_CRED_ERR;
		}
		free(arggv);
		return PAM_SUCCESS;

	} else {		/* child */
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);
		}

		execv(arggv[0], arggv);
		int i = errno;
		pam_syslog(pamh, LOG_ERR, "execv(%s,...) failed: %m", arggv[0]);
		free(arggv);
		_exit(i);
	}

	return PAM_SYSTEM_ERR;	/* will never be reached. */
}

/*
 * Refresh the group policies of machine
 */
static int update_machine_policy(pam_handle_t * pamh, int debug)
{
	int retval;
	retval = pam_info(pamh, "Applying machine settings");
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	char **arggv;
	arggv = calloc(5, sizeof(char *));
	if (arggv == NULL) {
		return PAM_BUF_ERR;
	}

	arggv[0] = "/sbin/adsysctl";
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

	if (pid > 0) {		/* parent */
		pid_t retval;
		int status = 0;

		while ((retval = waitpid(pid, &status, 0)) == -1
		       && errno == EINTR) ;

		if (retval == (pid_t) - 1) {
			pam_syslog(pamh, LOG_ERR,
				   "waitpid returns with -1: %m");
			free(arggv);
			return PAM_SYSTEM_ERR;
		} else if (status != 0) {
			if (WIFEXITED(status)) {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update -m failed: exit code %d",
					   WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update -m failed: caught signal %d%s",
					   WTERMSIG(status),
					   WCOREDUMP(status) ? " (core dumped)"
					   : "");
			} else {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl update -m failed: unknown status 0x%x",
					   status);
			}
			free(arggv);
			return PAM_CRED_ERR;
		}
		free(arggv);
		return PAM_SUCCESS;

	} else {		/* child */
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);
		}

		execv(arggv[0], arggv);
		int i = errno;
		pam_syslog(pamh, LOG_ERR, "execv(%s,...) failed: %m", arggv[0]);
		free(arggv);
		_exit(i);
	}

	return PAM_SYSTEM_ERR;	/* will never be reached. */
}

/*
 * Set DCONF_PROFILE for current user
 */
static int set_dconf_profile(pam_handle_t * pamh, const char *username,
			     int debug)
{
	int retval = PAM_SUCCESS;

	char *envvar;
	if (asprintf(&envvar, "DCONF_PROFILE=%s", username) < 0) {
		pam_syslog(pamh, LOG_CRIT, "out of memory");
		return PAM_BUF_ERR;
	}

	retval = pam_putenv(pamh, envvar);
	_pam_drop(envvar);
	return retval;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int retval = PAM_SUCCESS;

	int debug = 0;
	int optargc;

	for (optargc = 0; optargc < argc; optargc++) {
		if (strcasecmp(argv[optargc], "debug") == 0) {
			debug = 1;
		} else {
			break;	/* Unknown option. */
		}
	}

	const char *username;
	if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS) {
		D(("pam_get_item failed for PAM_USER"));
		return PAM_SYSTEM_ERR;	/* let pam_get_item() log the error */
	}

	/*
	 * We consider that KRB5CCNAME is always set by SSSD for remote users
	 * We do an exception for GDM which is handled by the machine's GPO
	 * and we must set the DCONF_PROFILE environment variable.
	 */
	const char *krb5ccname = pam_getenv(pamh, "KRB5CCNAME");
	if (krb5ccname == NULL && strcmp(username, "gdm") != 0) {
		return PAM_IGNORE;
	}

	// set dconf profile for AD and gdm user.
	retval = set_dconf_profile(pamh, username, debug);
	if (retval != PAM_SUCCESS) {
		return retval;
	};

	/*
	  update user policy is only for AD users.
	*/
	if (strcmp(username, "gdm") == 0) {
		return PAM_IGNORE;
	}

	/*
	  trying to update machine policy first if no machine gpo cache (meaning adsysd boot service failed due to being offline for instance)
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

	return update_policy(pamh, username, krb5ccname, debug);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
	return PAM_SUCCESS;
}

/* end of module definition */
