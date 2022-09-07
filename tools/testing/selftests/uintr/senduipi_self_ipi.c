// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <x86gprintrin.h>

#include "uintr_common.h"

volatile int uintr_received;
int uipi_index;
int uipi_index_2;
int nerrs;

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame,
						     unsigned long long vector)
{
		uintr_received = 1;
}

static inline void cpu_delay_long(void)
{
	long long dl = 1000;
	volatile long long cnt = dl << 10;

	while (cnt--)
		dl++;
}

static inline void cpu_delay_short(void)
{
	long long dl = 1000;
	volatile long long cnt = 10;

	while (cnt--)
		dl++;
}

static int setup_uintr_self_ipi(void)
{
	int uvec_fd;

	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	uvec_fd = uintr_vector_fd(0, 0);
	if (uvec_fd < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	_stui();

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		close(uvec_fd);
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	return 0;
}

void test_self_ipi_no_delay(void)
{
	uintr_received = 0;

	printf("[RUN]\tSelf IPI: No delay\n");

	_senduipi(uipi_index);

	if (uintr_received) {
		printf("[OK]\tSelf IPI: Interrupt received\n");
	} else {
		printf("[FAIL]\tSelf IPI: Interrupt not received\n");
		nerrs++;
	}

	while(!uintr_received);
}

void test_self_ipi_short_delay(void)
{
	uintr_received = 0;

	printf("[RUN]\tSelf IPI: Short delay\n");

	_senduipi(uipi_index);

	cpu_delay_short();

	if (uintr_received) {
		printf("[OK]\tSelf IPI: Interrupt received\n");
	} else {
		printf("[FAIL]\tSelf IPI: Interrupt not received\n");
		nerrs++;
	}

	while(!uintr_received);
}

void test_self_ipi_long_delay(void)
{
	uintr_received = 0;

	printf("[RUN]\tSelf IPI: Long delay\n");

	_senduipi(uipi_index);

	cpu_delay_long();

	if (uintr_received) {
		printf("[OK]\tSelf IPI: Interrupt received\n");
	} else {
		printf("[FAIL]\tSelf IPI: Interrupt not received\n");
		nerrs++;
	}

	while(!uintr_received);
}

void test_self_ipi_syscall_delay(void)
{
	uintr_received = 0;

	printf("[RUN]\tSelf IPI: syscall delay\n");

	_senduipi(uipi_index);

	usleep(1);

	if (uintr_received) {
		printf("[OK]\tSelf IPI: Interrupt received\n");
	} else {
		printf("[FAIL]\tSelf IPI: Interrupt not received\n");
		nerrs++;
	}

	while(!uintr_received);
}

static void *receiver_thread_no_fd(void *arg)
{
	int vector = 2;

	if (uintr_register_handler(uintr_empty_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		pthread_exit(NULL);
	}

	/* Create uvec_fd */
	uipi_index_2 = uintr_register_self(vector, 0);
	if (uipi_index_2 < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		pthread_exit(NULL);
	}

	_stui();

	while(!uintr_received);

	return NULL;
}

void test_self_ipi_twice(void)
{
	pthread_t pt;

	uintr_received = 0;

	if (pthread_create(&pt, NULL, &receiver_thread_no_fd, NULL)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	printf("[RUN]\tSelf IPI: SENDUIPI twice (different destinations)\n");

	_senduipi(uipi_index);

	/* Check if the second senduipi waits for the first local apic write to complete? */
	_senduipi(uipi_index_2);

	if (uintr_received) {
		printf("[OK]\tSelf IPI: Interrupt received\n");
	} else {
		printf("[FAIL]\tSelf IPI: Interrupt not received\n");
		nerrs++;
	}

	while(!uintr_received);
	pthread_join(pt, NULL);
}


int main(void)
{
	if (!uintr_supported())
		return EXIT_SUCCESS;

	if (setup_uintr_self_ipi())
		return 0;

	/*
	 * Self IPIs are not expected to be delivered directly after a SENDUIPI
	 * instr. They might be some delay in receiving them. The tests with
	 * short or no delay might fail.
	 */

	// test_self_ipi_no_delay();

	// test_self_ipi_short_delay();

	// test_self_ipi_twice();

	/*
	 * Self IPIs with longer delays should typically pass. If they fail
	 * consistently then there might be an underlying issue.
	 */

	test_self_ipi_long_delay();

	test_self_ipi_syscall_delay();

	return nerrs ? EXIT_FAILURE : EXIT_SUCCESS;
}
