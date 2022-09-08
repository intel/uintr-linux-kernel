/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_UINTR_H
#define _UAPI_LINUX_UINTR_H

#include <linux/types.h>

/* uvec_fd IOCTLs */
#define UINTR_BASE		'U'
#define UINTR_IS_ACTIVE		_IO(UINTR_BASE, 0)
#define UINTR_DISABLE		_IO(UINTR_BASE, 1)
#define UINTR_NOTIFY		_IO(UINTR_BASE, 2)

/* uipi_fd IOCTLs */
#define UINTR_UIPI_FD_BASE		'u'
#define UIPI_SET_TARGET_TABLE		_IO(UINTR_UIPI_FD_BASE, 0)
/* Not supported for now. UITT clearing is an involved process */
#define UIPI_CLEAR_TARGET_TABLE		_IO(UINTR_UIPI_FD_BASE, 1)

#endif
