// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <x86gprintrin.h>

#include "../../../../arch/x86/include/uapi/asm/uintr.h"

#ifndef __x86_64__
# error This test is 64-bit only
#endif

#ifndef __NR_uintr_register_handler
#define __NR_uintr_register_handler	471
#define __NR_uintr_unregister_handler	472
#define __NR_uintr_vector_fd		473
#define __NR_uintr_register_sender	474
#define __NR_uintr_unregister_sender	475
#define __NR_uintr_wait			476
#endif

#define uintr_register_handler(handler, flags)	syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags)		syscall(__NR_uintr_unregister_handler, flags)
#define uintr_vector_fd(vector, flags)		syscall(__NR_uintr_vector_fd, vector, flags)
#define uintr_register_sender(fd, flags)	syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(ipi_idx, flags)	syscall(__NR_uintr_unregister_sender, ipi_idx, flags)
#define uintr_wait(usec, flags)			syscall(__NR_uintr_wait, usec, flags)

unsigned long uintr_received;
unsigned int uvec_fd;

void __attribute__((interrupt))__attribute__((target("general-regs-only", "inline-all-stringops")))
uintr_handler(struct __uintr_frame *ui_frame,
	      unsigned long long vector)
{
	uintr_received = 1;
}

void *sender_thread(void *arg)
{
	long sleep_usec = (long)arg;
	int uipi_index;

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		printf("[FAIL]\tSender register error\n");
		return NULL;
	}

	/* Sleep before sending IPI to allow the receiver to block in the kernel */
	if (sleep_usec)
		usleep(sleep_usec);

	printf("\tother thread: sending IPI\n");
	_senduipi(uipi_index);

	uintr_unregister_sender(uipi_index, 0);

	return NULL;
}

static inline void cpu_relax(void)
{
	asm volatile("rep; nop" ::: "memory");
}

void test_base_ipi(void)
{
	int vector = 0;
	pthread_t pt;
	int ret;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[FAIL]\tInterrupt handler register error\n");
		exit(EXIT_FAILURE);
	}

	/* Create uvec_fd */
	ret = uintr_vector_fd(vector, 0);
	if (ret < 0) {
		printf("[FAIL]\tInterrupt vector registration error\n");
		exit(EXIT_FAILURE);
	}

	uvec_fd = ret;

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	if (pthread_create(&pt, NULL, &sender_thread, NULL)) {
		printf("[FAIL]\tError creating sender thread\n");
		return;
	}

	printf("[RUN]\tSpin in userspace (waiting for interrupts)\n");
	// Keep spinning until interrupt received
	while (!uintr_received)
		cpu_relax();

	printf("[OK]\tUser interrupt received\n");

	close(uvec_fd);
	uintr_unregister_handler(0);
}

void test_blocking_ipi(void)
{
	long sleep_usec;
	int vector = 0;
	pthread_t pt;
	int ret;

	/* Register interrupt handler */
	if (uintr_register_handler(uintr_handler, UINTR_HANDLER_FLAG_WAITING_ANY)) {
		/* Skip this test if blocking support is absent in the kernel */
		printf("[SKIP]\tInterrupt handler register error\n");
		exit(EXIT_SUCCESS);
	}

	/* Create uvec_fd */
	ret = uintr_vector_fd(vector, 0);
	if (ret < 0) {
		printf("[FAIL]\tInterrupt vector registration error\n");
		exit(EXIT_FAILURE);
	}

	uvec_fd = ret;

	/* Enable interrupts */
	_stui();

	uintr_received = 0;
	sleep_usec = 1000;
	if (pthread_create(&pt, NULL, &sender_thread, (void *)sleep_usec)) {
		printf("[FAIL]\tError creating sender thread\n");
		return;
	}

	printf("[RUN]\tBlock in the kernel (waiting for interrupts)\n");
	ret = uintr_wait(1000000, 0);

	if (ret && (errno == EINTR) && uintr_received)
		printf("[OK]\tUser interrupt received\n");
	else
		printf("[FAIL]\tUser interrupt not received during syscall\n");

	close(uvec_fd);
	uintr_unregister_handler(0);
}

int main(int argc, char *argv[])
{
	test_base_ipi();

	test_blocking_ipi();

	exit(EXIT_SUCCESS);
}
