/*
 * lehttpd.c
 *
 * Copyright (C) 2016 - 2017	Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the MIT license. See COPYING.
 */

#define _FILE_OFFSET_BITS 64

#define _BSD_SOURCE			/* For glibc < 2.19 */
#define _DEFAULT_SOURCE			/* setgroups(2) */
#define _XOPEN_SOURCE			/* chroot(2) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <microhttpd.h>

#define RUNAS		"nobody"

#define pr_log(...) \
	do { \
		fprintf(stdout, "lehttpd: " __VA_ARGS__); \
		fflush(stdout); \
	} while (0)

static int send_file(const char *url, struct MHD_Connection *connection)
{
	int ret;
	int fd;
	struct MHD_Response *response;
	struct stat sb;
	char *ptr;

	pr_log("Got reauest for: %s\n", url);

	ptr = strrchr(url, '/');
	ptr++;

	if (ptr[0] == '.')
		return MHD_NO;

	fd = open(ptr, O_RDONLY);
	if (fd == -1)
		return MHD_NO;
	fstat(fd, &sb);

	pr_log("Sending: %s\n", ptr);
	response = MHD_create_response_from_fd(sb.st_size, fd);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        return ret;
}

static int handle_request(void *cls, struct MHD_Connection *connection,
			  const char *url, const char *method,
			  const char *version, const char *upload_data,
			  size_t *upload_data_size, void **ptr)
{
	static int dummy;
	int ret;

	if (strcmp(method, "GET") != 0)
		return MHD_NO; /* unexpected method */

	if (&dummy != *ptr) {
		/*
		 * The first time only the headers are valid
		 * do not respond in the first round...
		 */
		*ptr = &dummy;
		return MHD_YES;
	}
	if (*upload_data_size != 0)
		return MHD_NO; /* upload data in a GET!? */

	*ptr = NULL; /* clear context pointer */

	ret = send_file(url, connection);

	return ret;
}

int main(int argc, char *argv[])
{
	struct MHD_Daemon *mhd;
	struct passwd *pwd = getpwnam(RUNAS);
	int ret;
	int mhd_flags = MHD_USE_SELECT_INTERNALLY | MHD_USE_IPv6 |
		MHD_USE_DUAL_STACK;

	if (argc < 2) {
		printf("Usage: lehttpd </path/to/chllenge-dir>\n");
		exit(EXIT_FAILURE);
	}

	pr_log("Changing directory to %s\n", argv[1]);
	ret = chdir(argv[1]);
	if (ret == -1) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	pr_log("Chroot'ing to %s\n", argv[1]);
	ret = chroot(argv[1]);
	if (ret == -1) {
		perror("chroot");
		exit(EXIT_FAILURE);
	}

	pr_log("Starting daemon with pid %d as uid %d\n", getpid(), geteuid());
	mhd = MHD_start_daemon(mhd_flags, 80, NULL, NULL, &handle_request,
			NULL, MHD_OPTION_END);
	if (!mhd)
		exit(EXIT_FAILURE);

	/* Drop root's supplimentary groups */
	ret = setgroups(0, NULL);
	if (ret == -1) {
		perror("setgroups");
		exit(EXIT_FAILURE);
	}

	/* Switch user */
	pr_log("Switching to user %s\n", RUNAS);
	ret = setgid(pwd->pw_gid);
	if (ret == -1) {
		perror("setgid");
		exit(EXIT_FAILURE);
	}
	ret = setuid(pwd->pw_uid);
	if (ret == -1) {
		perror("setuid");
		exit(EXIT_FAILURE);
	}
	pr_log("Now running as uid %d\n", getuid());

	sleep(60);

	pr_log("Shutting down...\n");
	MHD_stop_daemon(mhd);

	exit(EXIT_SUCCESS);
}
