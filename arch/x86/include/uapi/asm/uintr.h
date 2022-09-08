/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_UINTR_H
#define _UAPI_LINUX_UINTR_H

#include <linux/types.h>

/* uvec_fd IOCTLs */
#define UINTR_BASE		'U'
#define UINTR_IS_ACTIVE		_IO(UINTR_BASE, 0)
#define UINTR_DISABLE		_IO(UINTR_BASE, 1)
#define UINTR_NOTIFY		_IO(UINTR_BASE, 2)

#endif
