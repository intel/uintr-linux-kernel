// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 */
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <x86gprintrin.h>

#include "uintr_common.h"

unsigned long long uintr_expected_sp;
volatile int uintr_on_expected_stack;
volatile int uintr_received;
unsigned long long uintr_actual_stack;

int nerrs;

#define UINTR_ALT_STACK_SIZE	4096

unsigned long long getsp(void)
{
    unsigned long long sp;
    asm( "mov %%rsp, %0" : "=rm" (sp));
    return sp;
}

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame,
						     unsigned long long vector)
{
	uintr_received = 1;
	uintr_actual_stack = getsp();

	/* Checking if the current stack is within range */
	if ((uintr_actual_stack < uintr_expected_sp) && (uintr_actual_stack > (uintr_expected_sp - UINTR_ALT_STACK_SIZE)))
		uintr_on_expected_stack = 1;
}

static void test_alt_stack(void)
{
	int uvec_fd, uipi_index;
	void * uintr_sp;

	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uintr_sp = malloc(UINTR_ALT_STACK_SIZE);
	if (!uintr_sp) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	//printf("Alternate stack: Allocated stack:%llx\n", (unsigned long long)uintr_sp);
	uintr_alt_stack(uintr_sp, UINTR_ALT_STACK_SIZE, 0);

	uvec_fd = uintr_vector_fd(0, 0);
	if (uvec_fd < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	_stui();

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		close(uvec_fd);
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uintr_on_expected_stack = 0;
	uintr_received = 0;
	uintr_expected_sp = (unsigned long long)uintr_sp;

	printf("[RUN]\tAlternate stack: Test basic alternate stack\n");

	_senduipi(uipi_index);

	/* Wait for the interrupt to be received. Self IPI is also a posted delivery */
	while(!uintr_received);

	if (uintr_on_expected_stack) {
		printf("[OK]\tAlternate stack: Handler executed on alternate stack\n");
		printf("\tExpected stack: %llx Actual stack %llx\n", uintr_expected_sp, uintr_actual_stack);
	} else {
		printf("[FAIL]\tAlternate stack: Handler did not execute on alternate stack\n");
		printf("\tExpected stack: %llx Actual stack %llx\n", uintr_expected_sp, uintr_actual_stack);
		nerrs++;
	}

	close(uvec_fd);
	uintr_unregister_handler(0);
}

static void test_clear_alt_stack(void)
{
	int uvec_fd, uipi_index;
	void * uintr_sp;

	if (uintr_register_handler(uintr_handler, 0)) {
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uintr_sp = malloc(UINTR_ALT_STACK_SIZE);
	if (!uintr_sp) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	//printf("Alternate stack: Allocated stack:%llx\n", (unsigned long long)uintr_sp);
	uintr_alt_stack(uintr_sp, UINTR_ALT_STACK_SIZE, 0);

	uvec_fd = uintr_vector_fd(0, 0);
	if (uvec_fd < 0) {
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	_stui();

	uipi_index = uintr_register_sender(uvec_fd, 0);
	if (uipi_index < 0) {
		close(uvec_fd);
		uintr_unregister_handler(0);
		printf("[SKIP]\t%s:%d\n", __func__, __LINE__);
		return;
	}

	uintr_on_expected_stack = 0;
	uintr_received = 0;

	uintr_alt_stack(NULL, 0, 0);

	uintr_expected_sp = getsp();

	printf("[RUN]\tAlternate stack: Test clear alternate stack\n");

	_senduipi(uipi_index);

	/* Wait for the interrupt to be received. Self IPI is also a posted delivery */
	while(!uintr_received);

	if (uintr_on_expected_stack) {
		printf("[OK]\tAlternate stack: Handler executed on current stack\n");
		printf("\tExpected stack: %llx Actual stack %llx\n", uintr_expected_sp, uintr_actual_stack);
	} else {
		printf("[FAIL]\tAlternate stack: Handler did not execute on current stack\n");
		printf("\tExpected stack: %llx Actual stack %llx\n", uintr_expected_sp, uintr_actual_stack);
		nerrs++;
	}

	close(uvec_fd);
	uintr_unregister_handler(0);
}

int main(void)
{
	if (!uintr_supported())
		return EXIT_SUCCESS;

	test_alt_stack();

	test_clear_alt_stack();

	return nerrs ? EXIT_FAILURE : EXIT_SUCCESS;
}
