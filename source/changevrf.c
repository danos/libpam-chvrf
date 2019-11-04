/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, Brocade Communications Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE
#define PAM_SM_SESSION

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#ifdef RTNLGRP_RTDMN
#include <linux/rtg_domains.h>
#endif
#include <security/pam_modules.h>

static int change_vrf(pid_t pid, unsigned int rd)
{
	char *rd_path = NULL, *str_rd = NULL;
	char prev_rd[32];
	int fd = -1, rc = -1, n = 0, total_bytes = 0;

	if (asprintf(&str_rd, "%d", rd) < 0) {
		fprintf(stderr, "Cannot allocate memory for str_rd: %s\n",
			strerror(errno));
		goto fail;
	}

	if (asprintf(&rd_path, "/proc/%d/rtg_domain", pid) < 0) {
		fprintf(stderr, "Cannot allocate memory for rd_path: %s\n",
			strerror(errno));
		goto fail;
	}

	fd = open(rd_path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file /proc/%d/rtg_domain: %s\n",
			pid, strerror(errno));
		goto fail;
	}

	while (1) {
		n = read(fd,
			&prev_rd[total_bytes],
			sizeof(prev_rd) - total_bytes - 1);

		if (n < 0) {
			fprintf(stderr,
				"Failed to read rd from file /proc/%d/rtg_domain: %s\n",
				pid, strerror(errno));
			goto fail;
		}
		if (n > 0) {
			total_bytes += n;
			if (total_bytes > (sizeof(prev_rd) - 1)) {
				fprintf(stderr,
					"rdid read exceeds maximum size: %d\n",
					total_bytes);
				goto fail;
			}
		} else {
			prev_rd[total_bytes] = '\0';
			break;
		}
	}

	if (rd != atoi(prev_rd)) {
		if (strlen(str_rd) != write(fd, str_rd, strlen(str_rd))) {
			fprintf(stderr,
				"Failed to set rd in file /proc/%d/rtg_domain: %s\n",
				pid, strerror(errno));
			goto fail;
		}
	}

	rc = 0;

fail:
	if (fd != -1)
		close(fd);
	fflush(stdout);
	free(rd_path);
	free(str_rd);

	return rc;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
			int flags,
			int argc,
			const char **argv)
{
#ifdef RTNLGRP_RTDMN
	/* Change 'routing domain'/vrf of process to 1 (i.e. default) */
	if (change_vrf(getpid(), RD_DEFAULT) < 0)
		return PAM_SESSION_ERR;
#endif
	/* Note that with the upstream VRF solution, the process executed here
	 * does not inherit the cgroup associated with the VRF as usual, so no
	 * further action is needed to set it back into the default cgroup. This
	 * is because pam_systemd results in an implicit slice below user.slice
	 * being automatically created, i.e. not associated with the VRF.
	 */

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
			 int flags,
			 int argc,
			 const char **argv)
{
	return PAM_SUCCESS;
}
