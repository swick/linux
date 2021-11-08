// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <unistd.h>
#include <wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "pidfd.h"
#include "../kselftest_harness.h"

FIXTURE(sopeerpidfd) {
	/* accepted client fd */
	int client;
	/* accepted client pid */
	pid_t pid;
};

FIXTURE_SETUP(sopeerpidfd) {
	struct sockaddr_un addr;
	char sock_name[32];
	int sock, client_sock, pidfd, ret;
	socklen_t socklen;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_GE(sock, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(sock_name, "sopeerpidfd_test_%d", getpid());
	unlink(sock_name);
	strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path) - 1);

	ASSERT_EQ(bind(sock, (const struct sockaddr *)&addr,
		       sizeof(addr)), 0);

	ASSERT_EQ(listen(sock, 8), 0);

	self->pid = fork();
	ASSERT_GE(self->pid, 0);
	if (self->pid == 0) {
		client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_GE(client_sock, 0);

		ASSERT_EQ(connect(client_sock, (const struct sockaddr *)&addr, sizeof(addr)), 0);

		EXPECT_EQ(close(client_sock), 0);
		exit(EXIT_SUCCESS);
	}

	self->client = accept(sock, NULL, NULL);
	ASSERT_GE(self->client, 0);

	EXPECT_EQ(unlink(sock_name), 0);

	EXPECT_EQ(close(sock), 0);

	socklen = sizeof(pidfd);
	ret = getsockopt(self->client, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen);

	EXPECT_EQ(ret, 0) {
		ASSERT_EQ(errno, ENOPROTOOPT);
		SKIP(return, "SO_PEERPIDFD not supported");
	}

	EXPECT_EQ(close(pidfd), 0);
}

FIXTURE_TEARDOWN(sopeerpidfd) {
	if (self->client != 0)
		EXPECT_EQ(close(self->client), 0);
	if (self->pid > 0)
		EXPECT_GE(waitpid(self->pid, NULL, 0), 0);
}

TEST_F(sopeerpidfd, basic) {
	int pidfd;
	socklen_t socklen;

	socklen = sizeof(pidfd);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen), 0);

	EXPECT_EQ(socklen, sizeof(pidfd));
	EXPECT_GE(pidfd, 0);

	EXPECT_EQ(close(pidfd), 0);
}

TEST_F(sopeerpidfd, socklen) {
	int pidfd = 42;
	socklen_t socklen;

	socklen = 0;
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen), 0);
	EXPECT_EQ(pidfd, 42);
}

static int safe_int(const char *numstr, int *converted)
{
	char *err = NULL;
	long sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	if (sli > INT_MAX || sli < INT_MIN)
		return -ERANGE;

	*converted = (int)sli;
	return 0;
}

static int char_left_gc(const char *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;

		return i;
	}

	return 0;
}

static int char_right_gc(const char *buffer, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == ' '  ||
		    buffer[i] == '\t' ||
		    buffer[i] == '\n' ||
		    buffer[i] == '\0')
			continue;

		return i + 1;
	}

	return 0;
}

static char *trim_whitespace_in_place(char *buffer)
{
	buffer += char_left_gc(buffer, strlen(buffer));
	buffer[char_right_gc(buffer, strlen(buffer))] = '\0';
	return buffer;
}

static pid_t get_pid_from_fdinfo_file(int pidfd, const char *key, size_t keylen)
{
	int ret;
	char path[512];
	FILE *f;
	size_t n = 0;
	pid_t result = -1;
	char *line = NULL;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);

	f = fopen(path, "re");
	if (!f)
		return -1;

	while (getline(&line, &n, f) != -1) {
		char *numstr;

		if (strncmp(line, key, keylen))
			continue;

		numstr = trim_whitespace_in_place(line + 4);
		ret = safe_int(numstr, &result);
		if (ret < 0)
			goto out;

		break;
	}

out:
	free(line);
	fclose(f);
	return result;
}

TEST_F(sopeerpidfd, pid_match) {
	int pidfd;
	socklen_t socklen;
	pid_t pid;

	socklen = sizeof(pidfd);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen), 0);

	EXPECT_EQ(socklen, sizeof(pidfd));
	EXPECT_GE(pidfd, 0);

	pid = get_pid_from_fdinfo_file(pidfd, "Pid:", sizeof("Pid:") - 1);
	ASSERT_EQ(self->pid, pid);

	EXPECT_EQ(close(pidfd), 0);
}

TEST_HARNESS_MAIN
