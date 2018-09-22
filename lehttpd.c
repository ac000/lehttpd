/*
 * lehttpd.c
 *
 * Copyright (C) 2016 - 2018	Andrew Clayton <andrew@digital-domain.net>
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
#include <errno.h>
#ifdef _HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#include <microhttpd.h>

#define RUNAS		"nobody"
#define ACME_CHAL_PRFX	"/.well-known/acme-challenge/"

#define pr_log(...) \
	do { \
		fprintf(stdout, "lehttpd: " __VA_ARGS__); \
		fflush(stdout); \
	} while (0)

static void init_seccomp(void)
{
#ifdef _HAVE_LIBSECCOMP
	int err;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
	if (ctx == NULL)
		goto no_seccomp;

	/* Restrict open() to read only */
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_CMP(0, SCMP_CMP_EQ, STDOUT_FILENO));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_CMP(0, SCMP_CMP_EQ, STDERR_FILENO));

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

	/* For libmicrohttpd */
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

	/*
	 * Not sure, needed for CentOS 7 since around May 2018
	 *
	 * Weird thing is on a CentOS 7 vm @ Vultr I see different
	 * syscalls than that of a CentOS 7 vm running locally. Both
	 * are on the same kernel, glibc, libmicrohttpd ...
	 */
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	err = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
	if (err) {
		pr_log("SCMP_FLTATR_CTL_TSYNC seccomp flag not available, needs Linux 3.17+\n");
		goto no_seccomp;
	}

	err = seccomp_load(ctx);
	if (!err) {
		pr_log("Initialised seccomp\n");
		seccomp_release(ctx);
		return;
	}

no_seccomp:
	seccomp_release(ctx);
	pr_log("Seccomp initialisation failed. Check kernel config?\n");
	pr_log("Continuing without seccomp\n");
#else
	pr_log("Not built with libseccomp support. Not using seccomp\n");
#endif
}

static int send_file(const char *url, struct MHD_Connection *connection)
{
	int ret;
	int fd;
	struct MHD_Response *response;
	struct stat sb;
	char *ptr;

	pr_log("Got request for: %s\n", url);
	if (strncmp(url, ACME_CHAL_PRFX, strlen(ACME_CHAL_PRFX)) != 0) {
		pr_log("Not from letsencrypt. Ignoring\n");
		return MHD_NO;
	}

	ptr = strrchr(url, '/');
	ptr++;

	if (ptr[0] == '.')
		return MHD_NO;

	fd = open(ptr, O_RDONLY);
	if (fd == -1)
		return MHD_NO;
	fstat(fd, &sb);
	if ((sb.st_mode & S_IFMT) != S_IFREG)
		return MHD_NO;

	pr_log("Sending: %s\n", ptr);
	response = MHD_create_response_from_fd(sb.st_size, fd);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        return ret;
}

static int handle_request(__attribute__ ((unused)) void *cls,
			  struct MHD_Connection *connection,
			  const char *url, const char *method,
			  __attribute__ ((unused)) const char *version,
			  __attribute__ ((unused)) const char *upload_data,
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

	init_seccomp();
	sleep(60);

	pr_log("Shutting down...\n");
	MHD_stop_daemon(mhd);

	exit(EXIT_SUCCESS);
}
