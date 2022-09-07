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

/* This check doesn't fail. */
static void print_uintr_support(void)
{
	printf("[RUN]\tCheck if User Interrupts (UINTR) is supported\n");
	if (uintr_supported())
		printf("[OK]\tUser Interrupts (UINTR) is supported\n");
	else
		printf("[OK]\tUser Interrupts (UINTR) is not supported. Skipping rest of the tests silently\n");
}

static void *sender_thread_no_fd(void *arg)
{
	int  uipi_index = *(int *)arg;

	printf("\tother thread: sending IPI (no fd)\n");
	_senduipi(uipi_index);

	uintr_unregister_sender(uipi_index, 0);

	return NULL;
}

static void *sender_thread(void *arg)
{
	int  uvec_fd = *(int *)arg;
	int uipi_index;

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		printf("[FAIL]\tSender register error\n");
		return NULL;
	}

	/* Sleep before sending IPI to allow the receiver to start waiting */
	usleep(100);

	printf("\tother thread: sending IPI\n");
	_senduipi(uipi_index);

	uintr_unregister_sender(uipi_index, 0);

	return NULL;
}

static void test_thread_ipi(void)
{
	int wait_for_delay = 100000;
	int vector = 0;
	int uvec_fd;
	pthread_t pt;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd */
	uvec_fd = uintr_vector_fd(vector, 0);
	if (uvec_fd < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	if (pthread_create(&pt, NULL, &sender_thread, (void *)&uvec_fd)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	printf("[RUN]\tBase UIPI test: pthreads\n");
	printf("\tSpin in userspace (waiting for interrupts)\n");
	// Keep spinning until interrupt received
	while (wait_for_delay-- && !uintr_received)
		cpu_delay();

	if (uintr_received) {
		printf("[OK]\tUser interrupt received\n");
	} else {
		printf("[FAIL]\tUser interrupt not received\n");
		nerrs++;
	}

	pthread_join(pt, NULL);
	close(uvec_fd);
	uintr_unregister_handler(0);
}

static void test_thread_ipi_no_fd(void)
{
	int wait_for_delay = 100000;
	int vector = 0;
	int uipi_index;
	pthread_t pt;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd */
	uipi_index = uintr_register_self(vector, 0);
	if (uipi_index < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	if (pthread_create(&pt, NULL, &sender_thread_no_fd, (void *)&uipi_index)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	printf("[RUN]\tBase UIPI test: pthreads\n");
	printf("\tSpin in userspace (waiting for interrupts)\n");
	// Keep spinning until interrupt received
	while (wait_for_delay-- && !uintr_received)
		cpu_delay();

	if (uintr_received) {
		printf("[OK]\tUser interrupt received\n");
	} else {
		printf("[FAIL]\tUser interrupt not received\n");
		nerrs++;
	}

	pthread_join(pt, NULL);
	uintr_unregister_handler(0);
}

static void test_blocking_ipi_uintr_wait(unsigned int flags)
{
	int ret, uvec_fd;
	int vector = 0;
	pthread_t pt;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, flags)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd */
	uvec_fd = uintr_vector_fd(vector, 0);
	if (uvec_fd < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	if (pthread_create(&pt, NULL, &sender_thread, (void *)&uvec_fd)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	printf("[RUN]\tBase UIPI test: pthreads\n");
	printf("\tBlock in the kernel (using uintr_wait()) %s pays the cost\n",
	       flags == UINTR_HANDLER_FLAG_WAITING_RECEIVER ? "receiver" : "sender");
	ret = uintr_wait(100000, 0);
	if (ret && (errno == EINTR) && uintr_received) {
		printf("[OK]\tUser interrupt received during the syscall\n");
	} else {
		printf("[FAIL]\tUser interrupt not received during the syscall\n");
		nerrs++;
	}

	pthread_join(pt, NULL);
	close(uvec_fd);
	uintr_unregister_handler(0);
}

static void test_blocking_ipi_sleep(unsigned int flags)
{
	int ret, uvec_fd;
	int vector = 0;
	pthread_t pt;
	struct timespec req, rem;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, flags)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Create uvec_fd */
	uvec_fd = uintr_vector_fd(vector, 0);
	if (uvec_fd < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	if (pthread_create(&pt, NULL, &sender_thread, (void *)&uvec_fd)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	printf("[RUN]\tBase UIPI test: pthreads\n");
	printf("\tBlock in the kernel (using nanosleep()) %s pays the cost\n",
	       flags == UINTR_HANDLER_FLAG_WAITING_RECEIVER ? "receiver" : "sender");

	req.tv_sec = 10;
	req.tv_nsec = 0;

	ret = nanosleep(&req, &rem);

	if (ret && (errno == EINTR) && uintr_received) {
		printf("[OK]\tUser interrupt received during the syscall\n");
	} else {
		printf("[FAIL]\tUser interrupt not received during the syscall\n");
		nerrs++;
	}

	pthread_join(pt, NULL);
	close(uvec_fd);
	uintr_unregister_handler(0);
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

	pause();
}

static void test_process_ipi_unidirectional(void)
{
	int wait_for_usec = 10000;
	int uvec_fd, pid;

	if (uintr_register_handler(uintr_handler, 0)) {
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

	printf("[RUN]\tBase User IPI test: Process uni-directional\n");

	pid = fork();
	if (pid == 0) {
		/* Child sender process */
		sender_process_uni(uvec_fd);
		exit(EXIT_SUCCESS);
	}

	/* FIXME: Using usleep(1) instead of cpu_delay() causes the test to fail sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (wait_for_usec-- && !uintr_received) {
		//usleep(1);
		cpu_delay();
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

static void client_process_bi(int server_fd, int sock)
{
	int uipi_index;
	int client_fd;
	ssize_t size;

	uipi_index = uintr_register_sender(server_fd, 0);
	if (uipi_index < 0) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (uintr_register_handler(client_handler, 0)) {
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

	/* FIXME: Using usleep(1) instead of cpu_delay() causes the test to fail sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (!client_received) {
		//usleep(1);
		cpu_delay();
	}

	_senduipi(uipi_index);

	pause();
}

static void test_process_ipi_bidirectional(void)
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

	if (uintr_register_handler(server_handler, 0)) {
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

	printf("[RUN]\tBase User IPI test: Process bi-directional\n");

	pid = fork();
	if (pid == 0) {
		/* Child client process */
		close(sv[0]);
		client_process_bi(server_fd, sv[1]);
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

	/* FIXME: Using usleep(1) instead of cpu_delay() causes the test to fail sometimes. This is likely related to racing in the GP fix handler for blocking */
	while (!server_received) {
		//usleep(1);
		cpu_delay();
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

/* TODO: Use some better method for failure rather than the 45sec KSFT timeout */
int main(int argc, char *argv[])
{
	print_uintr_support();

	if (!uintr_supported())
		return EXIT_SUCCESS;

	test_thread_ipi();

	test_thread_ipi_no_fd();

	test_blocking_ipi_uintr_wait(UINTR_HANDLER_FLAG_WAITING_RECEIVER);

	test_blocking_ipi_sleep(UINTR_HANDLER_FLAG_WAITING_RECEIVER);

	test_blocking_ipi_uintr_wait(UINTR_HANDLER_FLAG_WAITING_SENDER);

	test_blocking_ipi_sleep(UINTR_HANDLER_FLAG_WAITING_SENDER);

	test_process_ipi_unidirectional();

	test_process_ipi_bidirectional();

	return nerrs ? EXIT_FAILURE : EXIT_SUCCESS;
}
