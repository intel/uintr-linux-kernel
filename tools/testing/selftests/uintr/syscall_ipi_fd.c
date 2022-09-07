// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <x86gprintrin.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "uintr_common.h"

unsigned int nerrs;
unsigned int uintr_received;

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame,
						     unsigned long long vector)
{
	uintr_received = 1;
}

static void child_sender_process(int sock)
{
	int uipi_index;
	int uipi_fd;
	int ret;
	char buf[16];

	if (sock_fd_read(sock, buf, sizeof(buf), &uipi_fd) != 1) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	ret = ioctl(uipi_fd, UIPI_SET_TARGET_TABLE);
	if (ret) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Fix: Currently, assume if uipi_fd is valid then uipi_index of 0 is valid */
	uipi_index = 0;

	_senduipi(uipi_index);

	pause();
}

static void test_share_ipi_fd(void)
{
	int uipi_fd, uipi_index, pid;
	int sv[2];
	ssize_t size;
	int vector = 0;
	int wait_for_usec;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0)  {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	pid = fork();
	if (pid == 0) {
		/* Child client process */
		close(sv[0]);
		child_sender_process(sv[1]);
		exit(EXIT_SUCCESS);
	}

	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Register self as sender */
	uipi_index = uintr_register_self(vector, 0);
	if (uipi_index < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uipi_fd = uintr_ipi_fd(0);
	if (uipi_fd < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}
	_stui();

	printf("[RUN]\tBase IPI FD test: share ipi FD\n");

	close(sv[1]);
	if (sock_fd_write(sv[0], "1", 1, uipi_fd) != 1) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	wait_for_usec = 10000000;
	while (!uintr_received && wait_for_usec--)
		cpu_delay();

	//close(uvec_fd);
	uintr_unregister_handler(0);
	kill(pid, SIGKILL);

	if (!uintr_received) {
		printf("[FAIL]\tUser interrupt not received\n");
		nerrs++;
	} else {
		printf("[OK]\tUser interrupt received\n");
	}
}

int main(int argc, char *argv[])
{
	if (!uintr_supported())
		return EXIT_SUCCESS;

	test_share_ipi_fd();

	// test_inherit_ipi_fd();

	return nerrs ? EXIT_FAILURE : EXIT_SUCCESS;
}
