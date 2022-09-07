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

#include "uintr_common.h"

unsigned int uintr_received;
unsigned int client_received;
unsigned int server_received;
unsigned int nerrs;

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame,
						     unsigned long long vector)
{
	uintr_received = 1;
}

static void __attribute__((interrupt)) client_handler(struct __uintr_frame *ui_frame,
						      unsigned long long vector)
{
	client_received = 1;
}

static void __attribute__((interrupt)) server_handler(struct __uintr_frame *ui_frame,
						      unsigned long long vector)
{
	server_received = 1;
}

static void sender_process_uni(int uvec_fd)
{
	int uipi_index;

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		exit(EXIT_FAILURE);
	}

	_senduipi(uipi_index);

	uintr_unregister_sender(uipi_index, 0);
	/* Close sender copy of uvec_fd */
	close(uvec_fd);

	sleep(3);

	//pause();
}

static void test_process_ipi_unidirectional(unsigned int handler_flags)
{
	int wait_for_usec = 10000;
	int uvec_fd, pid;

	if (uintr_register_handler(uintr_handler, handler_flags)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uvec_fd = uintr_vector_fd(0, 0);
	if (uvec_fd < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uintr_received = 0;
	_stui();

	printf("[RUN]\tBlocking test: Process uni-directional\n");
	printf("\tBlock in the kernel (using usleep(1)) %s pays the cost\n",
	       handler_flags == UINTR_HANDLER_FLAG_WAITING_RECEIVER ? "receiver" : "sender");

	pid = fork();
	if (pid == 0) {
		/* Child sender process */
		sender_process_uni(uvec_fd);
		exit(EXIT_SUCCESS);
	}

	/* FIXME: Using usleep(1) causes the test to hang/pause sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (wait_for_usec-- && !uintr_received) {
		usleep(1);
		//cpu_delay();
	}

	close(uvec_fd);
	uintr_unregister_handler(0);
	kill(pid, SIGKILL);

	if (!uintr_received) {
		printf("[FAIL]\tUser interrupt not received\n");
		nerrs++;
	} else {
		printf("[OK]\tUser interrupt received\n");
	}
}

static void client_process_bi(int server_fd, int sock, unsigned int handler_flags)
{
	int uipi_index;
	int client_fd;
	ssize_t size;

	uipi_index = uintr_register_sender(server_fd, 0);
	if (uipi_index < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (uintr_register_handler(client_handler, handler_flags)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd with vector 1 */
	client_fd = uintr_vector_fd(1, 0);
	if (client_fd < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}
	_stui();

	// Share client_fd
	if (sock_fd_write(sock, "1", 1, client_fd) != 1) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* FIXME: Using usleep(1) causes the test to hang/pause sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (!client_received) {
		usleep(1);
	}

	_senduipi(uipi_index);

	sleep(3);
	//pause();
}

static void test_process_ipi_bidirectional(unsigned int handler_flags)
{
	int server_fd, client_fd, pid;
	int sv[2];
	ssize_t size;
	char buf[16];
	int uipi_index;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0)  {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	if (uintr_register_handler(server_handler, handler_flags)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd with vector 0 */
	server_fd = uintr_vector_fd(0, 0);
	if (server_fd < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	_stui();

	printf("[RUN]\tBlocking test: Process bi-directional\n");
	printf("\tBlock in the kernel (using usleep(1)) %s pays the cost\n",
	       handler_flags == UINTR_HANDLER_FLAG_WAITING_RECEIVER ? "receiver" : "sender");

	pid = fork();
	if (pid == 0) {
		/* Child client process */
		close(sv[0]);
		client_process_bi(server_fd, sv[1], handler_flags);
		exit(EXIT_SUCCESS);
	}

	close(sv[1]);
	if (sock_fd_read(sv[0], buf, sizeof(buf), &client_fd) != 1) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	//Register server as sender
	uipi_index = uintr_register_sender(client_fd, 0);
	if (uipi_index < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	_senduipi(uipi_index);

	/* FIXME: Using usleep(1) causes the test to hang/pause sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (!server_received) {
		usleep(1);
	}

	//close(uvec_fd);
	uintr_unregister_handler(0);
	kill(pid, SIGKILL);

	if (!server_received) {
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

	test_process_ipi_unidirectional(UINTR_HANDLER_FLAG_WAITING_RECEIVER);

	test_process_ipi_bidirectional(UINTR_HANDLER_FLAG_WAITING_RECEIVER);

	test_process_ipi_unidirectional(UINTR_HANDLER_FLAG_WAITING_SENDER);

	test_process_ipi_bidirectional(UINTR_HANDLER_FLAG_WAITING_SENDER);

	return nerrs ? EXIT_FAILURE : EXIT_SUCCESS;
}
