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

/*
 * Refresh the group policies of current user
 */
static int update_policy(pam_handle_t * pamh, const char *username, int debug)
{
	const char *krb5ccname = pam_getenv(pamh, "KRB5CCNAME");
	if (krb5ccname == NULL) {
		pam_syslog(pamh, LOG_ERR, "KRB5CCNAME is not set");
		return PAM_ABORT;
	}

	if (memcmp(krb5ccname, (const char *)"FILE:", 5) == 0) {
		krb5ccname += 5;
	}

	char **arggv;
	arggv = calloc(7, sizeof(char *));
	if (arggv == NULL) {
		return PAM_SYSTEM_ERR;
	}

	arggv[0] = "/sbin/adsysctl";
	arggv[1] = "policy";
	arggv[2] = "update";
	arggv[3] = (char *)(username);
	arggv[4] = (char *)(krb5ccname);
	arggv[5] = NULL;
	if (debug) {
		arggv[5] = "-vv";
		arggv[6] = NULL;
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
					   "adsysctl policy update %s %s failed: exit code %d",
					   username, krb5ccname,
					   WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl policy update %s %s failed: caught signal %d%s",
					   username, krb5ccname,
					   WTERMSIG(status),
					   WCOREDUMP(status) ? " (core dumped)"
					   : "");
			} else {
				pam_syslog(pamh, LOG_ERR,
					   "adsysctl policy update %s %s failed: unknown status 0x%x",
					   username, krb5ccname, status);
			}
			free(arggv);
			return PAM_SYSTEM_ERR;
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
	// char *username = malloc(100);
	if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS) {
		D(("pam_get_item failed for PAM_USER"));
		return PAM_SYSTEM_ERR;	/* let pam_get_item() log the error */
	}

	/* check if it is a local or remote use
	 * is there a better/more reliable way?
	 */
	if (strchr(username, '@') == NULL) {
		return PAM_IGNORE;
	}

	retval = set_dconf_profile(pamh, username, debug);
	if (retval != PAM_SUCCESS) {
		return retval;
	};

	return update_policy(pamh, username, debug);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
	return PAM_SUCCESS;
}

/* end of module definition */
