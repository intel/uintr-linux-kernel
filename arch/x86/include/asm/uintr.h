/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_UINTR_H
#define _ASM_X86_UINTR_H

#ifdef CONFIG_X86_USER_INTERRUPTS

/* TODO: Separate out the hardware definitions from the software ones */
/* User Posted Interrupt Descriptor (UPID) */
struct uintr_upid {
	struct {
		u8 status;	/* bit 0: ON, bit 1: SN, bit 2-7: reserved */
		u8 reserved1;	/* Reserved */
		u8 nv;		/* Notification vector */
		u8 reserved2;	/* Reserved */
		u32 ndst;	/* Notification destination */
	} nc __packed;		/* Notification control */
	u64 puir;		/* Posted user interrupt requests */
} __aligned(64);

/* UPID Notification control status bits */
#define UINTR_UPID_STATUS_ON		0x0	/* Outstanding notification */
#define UINTR_UPID_STATUS_SN		0x1	/* Suppressed notification */

struct uintr_upid_ctx {
	struct list_head node;
	struct task_struct *task;	/* Receiver task */
	u64 uvec_mask;			/* track registered vectors per bit */
	struct uintr_upid *upid;
	/* TODO: Change to kernel kref api */
	refcount_t refs;
};

/* TODO: Inline the context switch related functions */
void switch_uintr_prepare(struct task_struct *prev);
void switch_uintr_return(void);

#else /* !CONFIG_X86_USER_INTERRUPTS */

static inline void switch_uintr_prepare(struct task_struct *prev) {}
static inline void switch_uintr_return(void) {}

#endif /* CONFIG_X86_USER_INTERRUPTS */

#endif /* _ASM_X86_UINTR_H */
