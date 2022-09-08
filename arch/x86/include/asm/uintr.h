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
#define UINTR_UPID_STATUS_BLKD		0x7	/* Blocked waiting for kernel */


struct uintr_upid_ctx {
	struct list_head node;
	struct task_struct *task;	/* Receiver task */
	u64 uvec_mask;			/* track registered vectors per bit */
	struct uintr_upid *upid;
	/* TODO: Change to kernel kref api */
	refcount_t refs;
	bool receiver_active;		/* Flag for UPID being mapped to a receiver */
	bool waiting;			/* Flag for UPID blocked in the kernel */
	unsigned int waiting_cost;	/* Flags for who pays the waiting cost */
};

/* UPID waiting cost */
#define UPID_WAITING_COST_NONE		0x0
#define UPID_WAITING_COST_RECEIVER	0x1
#define UPID_WAITING_COST_SENDER	0x2

/*
 * Each UITT entry is 16 bytes in size.
 * Current UITT table size is set as 4KB (256 * 16 bytes)
 */
#define UINTR_MAX_UITT_NR 256

/* User Interrupt Target Table Entry (UITTE) */
struct uintr_uitt_entry {
	u8	valid;			/* bit 0: valid, bit 1-7: reserved */
	u8	user_vec;
	u8	reserved[6];
	u64	target_upid_addr;
} __packed __aligned(16);

/* TODO: Remove uitt from struct names */
struct uintr_uitt_ctx {
	struct uintr_uitt_entry *uitt;
	/* Protect UITT */
	struct mutex uitt_lock;
	/* TODO: Change to kernel kref api */
	refcount_t refs;
	/* track active uitt entries per bit */
	u64 uitt_mask[BITS_TO_U64(UINTR_MAX_UITT_NR)];
	/* TODO: Might be useful to use xarray over here as the MAX size increases */
	struct uintr_upid_ctx *r_upid_ctx[UINTR_MAX_UITT_NR];
};

/* User IPI sender related functions */
struct uintr_uitt_ctx *get_uitt_ref(struct uintr_uitt_ctx *uitt_ctx);
void put_uitt_ref(struct uintr_uitt_ctx *uitt_ctx);
void uintr_destroy_uitt_ctx(struct mm_struct *mm);

bool is_uintr_sender(struct task_struct *t);
void uintr_set_sender_msrs(struct task_struct *t);
bool uintr_check_uitte_valid(struct uintr_uitt_ctx *uitt_ctx, unsigned int entry);

/* Uintr blocking related function */
void uintr_wake_up_process(void);
bool is_uintr_receiver(struct task_struct *t);
bool is_uintr_ongoing(struct task_struct *t);

/* UINTR kernel notification related functions */
struct file *uvecfd_fget(int uvec_fd);
int uintr_notify(struct file *uvec_f);

/* TODO: Inline the context switch related functions */
void switch_uintr_prepare(struct task_struct *prev);
void switch_uintr_return(void);
void switch_uintr_finish(struct task_struct *next);

void uintr_free(struct task_struct *task);

#else /* !CONFIG_X86_USER_INTERRUPTS */

static inline void uintr_destroy_uitt_ctx(struct mm_struct *mm) {}

static inline bool is_uintr_receiver(struct task_struct *t) { return false; }
static inline bool is_uintr_ongoing(struct task_struct *t) { return false; }

/* EXPORT_SYMBOL functions */
static inline int uintr_notify(struct file *uvec_f) { return -EINVAL; }
static inline struct file *uvecfd_fget(int uvec_fd) { return ERR_PTR(-EINVAL); }

static inline void switch_uintr_prepare(struct task_struct *prev) {}
static inline void switch_uintr_return(void) {}
static inline void switch_uintr_finish(struct task_struct *next) {}

static inline void uintr_free(struct task_struct *task) {}

#endif /* CONFIG_X86_USER_INTERRUPTS */

#endif /* _ASM_X86_UINTR_H */
