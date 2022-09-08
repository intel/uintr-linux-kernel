// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 * Jacob Pan <jacob.jun.pan@linux.intel.com>
 */
#define pr_fmt(fmt)    "uintr: " fmt

#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/hrtimer.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#include <asm/apic.h>
#include <asm/fpu/api.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/uintr.h>

#include <uapi/asm/uintr.h>

#define OS_ABI_REDZONE 128

struct uvecfd_ctx {
	struct uintr_upid_ctx *upid_ctx;	/* UPID context */
	u64 uvec;				/* Vector number */
#if 0
	//struct uintr_receiver_info *r_info;
	/* The previous version used the uvec_fd for lifecycle management. This version wouldn't do that */
	/* Protect sender_list */
	//spinlock_t sender_lock;
	//struct list_head sender_list;
#endif
};

/* Definitions to make the compiler happy */
static void uintr_remove_task_wait(struct task_struct *task);

/* TODO: To remove the global lock, move to a per-cpu wait list. */
static DEFINE_SPINLOCK(uintr_wait_lock);
static struct list_head uintr_wait_list = LIST_HEAD_INIT(uintr_wait_list);

inline bool is_uintr_receiver(struct task_struct *t)
{
	return !!t->thread.upid_activated;
}

inline bool is_uintr_ongoing(struct task_struct *t)
{
	return test_bit(UINTR_UPID_STATUS_ON,
			(unsigned long *)&t->thread.upid_ctx->upid->nc.status);
}

inline bool is_uintr_sender(struct task_struct *t)
{
	return !!t->thread.uitt_activated;
}

inline bool is_uintr_task(struct task_struct *t)
{
	return(is_uintr_receiver(t) || is_uintr_sender(t));
}

static void free_upid(struct uintr_upid_ctx *upid_ctx)
{
	put_task_struct(upid_ctx->task);
	kfree(upid_ctx->upid);
	upid_ctx->upid = NULL;
	kfree(upid_ctx);
}

static int check_upid_ref(struct uintr_upid_ctx *upid_ctx)
{
	return refcount_read(&upid_ctx->refs);
}

static void put_upid_ref(struct uintr_upid_ctx *upid_ctx)
{
	if (refcount_dec_and_test(&upid_ctx->refs)) {
		pr_debug("UPID: %px Decrement refcount=0 Freeing UPID\n",
			 upid_ctx->upid);
		free_upid(upid_ctx);
	} else {
		pr_debug("UPID: %px Decrement refcount=%d\n",
			 upid_ctx->upid,
			 check_upid_ref(upid_ctx));
	}
}

static struct uintr_upid_ctx *get_upid_ref(struct uintr_upid_ctx *upid_ctx)
{
	refcount_inc(&upid_ctx->refs);
	pr_debug("UPID: %px Increment refcount=%d\n",
		 upid_ctx->upid, refcount_read(&upid_ctx->refs));

	return upid_ctx;
}

/* TODO: UPID needs to be allocated by a KPTI compatible allocator */
static struct uintr_upid_ctx *alloc_upid(void)
{
	struct uintr_upid_ctx *upid_ctx;
	struct uintr_upid *upid;

	upid_ctx = kzalloc(sizeof(*upid_ctx), GFP_KERNEL);
	if (!upid_ctx)
		return NULL;

	upid = kzalloc(sizeof(*upid), GFP_KERNEL);

	if (!upid) {
		kfree(upid_ctx);
		return NULL;
	}

	upid_ctx->upid = upid;
	refcount_set(&upid_ctx->refs, 1);
	upid_ctx->task = get_task_struct(current);
	upid_ctx->receiver_active = true;
	upid_ctx->waiting = false;

	return upid_ctx;
}

/*
 * Vectors once registered always stay registered. Need a different syscall or
 * API to free them up
 */
static void do_uintr_unregister_vector(u64 uvec, struct uintr_upid_ctx *upid_ctx)
{
	//__clear_vector_from_upid(uvec, upid_ctx->upid);
	//__clear_vector_from_uirr(uvec);
	//__clear_vector_from_upid_ctx(uvec, upid_ctx);

	put_upid_ref(upid_ctx);

#if 0
	pr_debug("recv: Adding task work to clear vector %llu added for task=%d\n",
		 r_info->uvec, r_info->upid_ctx->task->pid);

	init_task_work(&r_info->twork, receiver_clear_uvec);
	ret = task_work_add(r_info->upid_ctx->task, &r_info->twork, true);
	if (ret) {
		pr_debug("recv: Clear vector task=%d has already exited\n",
			 r_info->upid_ctx->task->pid);
		kfree(r_info);
		return;
	}
#endif
}

#define UINTR_MAX_UVEC_NR 64

static int do_uintr_register_vector(u64 uvec, struct uintr_upid_ctx **uvecfd_upid_ctx)
{
	struct uintr_upid_ctx *upid_ctx;
	struct task_struct *t = current;

	/*
	 * A vector should only be registered by a task that
	 * has an interrupt handler registered.
	 */
	if (!is_uintr_receiver(t))
		return -EINVAL;

	if (uvec >= UINTR_MAX_UVEC_NR)
		return -ENOSPC;

	upid_ctx = t->thread.upid_ctx;

	/* Vectors once registered always stay registered */
	if (upid_ctx->uvec_mask & BIT_ULL(uvec))
		pr_debug("recv: task %d uvec=%llu was already registered\n",
			 t->pid, uvec);
	else
		upid_ctx->uvec_mask |= BIT_ULL(uvec);

	pr_debug("recv: task %d new uvec=%llu, new mask %llx\n",
		 t->pid, uvec, upid_ctx->uvec_mask);

	/* uvecfd_upid_ctx should be passed only when an FD is being created */
	if (uvecfd_upid_ctx)
		*uvecfd_upid_ctx = get_upid_ref(upid_ctx);

	return 0;
}

#ifdef CONFIG_PROC_FS
static void uvecfd_show_fdinfo(struct seq_file *m, struct file *file)
{
	struct uvecfd_ctx *uvecfd_ctx = file->private_data;

	/* Check: Should we print the receiver and sender info here? */
	seq_printf(m, "uintr: receiver: %d vector:%llu\n",
		   uvecfd_ctx->upid_ctx->task->pid,
		   uvecfd_ctx->uvec);
}
#endif

static int uvecfd_release(struct inode *inode, struct file *file)
{
	struct uvecfd_ctx *uvecfd_ctx = file->private_data;

	pr_debug("recv: Release uvecfd for r_task %d uvec %llu\n",
		 uvecfd_ctx->upid_ctx->task->pid,
		 uvecfd_ctx->uvec);

	do_uintr_unregister_vector(uvecfd_ctx->uvec, uvecfd_ctx->upid_ctx);
	kfree(uvecfd_ctx);

	return 0;
}

static const struct file_operations uvecfd_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= uvecfd_show_fdinfo,
#endif
	.release	= uvecfd_release,
	.llseek		= noop_llseek,
};

/*
 * sys_uintr_vector_fd - Create a uvec_fd for the registered interrupt vector.
 */
SYSCALL_DEFINE2(uintr_vector_fd, u64, vector, unsigned int, flags)
{
	struct uvecfd_ctx *uvecfd_ctx;
	int uvecfd;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	uvecfd_ctx = kzalloc(sizeof(*uvecfd_ctx), GFP_KERNEL);
	if (!uvecfd_ctx)
		return -ENOMEM;

	uvecfd_ctx->uvec = vector;
	ret = do_uintr_register_vector(uvecfd_ctx->uvec, &uvecfd_ctx->upid_ctx);
	if (ret)
		goto out_free_ctx;

	/* TODO: Get user input for flags - UFD_CLOEXEC */
	/* Check: Do we need O_NONBLOCK? */
	uvecfd = anon_inode_getfd("[uvecfd]", &uvecfd_fops, uvecfd_ctx,
				  O_RDONLY | O_CLOEXEC | O_NONBLOCK);

	if (uvecfd < 0) {
		ret = uvecfd;
		goto out_free_uvec;
	}

	pr_debug("recv: Alloc vector success uvecfd %d uvec %llu for task=%d\n",
		 uvecfd, uvecfd_ctx->uvec, current->pid);

	return uvecfd;

out_free_uvec:
	do_uintr_unregister_vector(uvecfd_ctx->uvec, uvecfd_ctx->upid_ctx);
out_free_ctx:
	kfree(uvecfd_ctx);
	pr_debug("recv: Alloc vector failed for task=%d ret %d\n",
		 current->pid, ret);
	return ret;
}

static inline bool is_uitt_empty(struct uintr_uitt_ctx *uitt_ctx)
{
	return !!bitmap_empty((unsigned long *)uitt_ctx->uitt_mask,
			      UINTR_MAX_UITT_NR);
}

static int check_uitt_ref(struct uintr_uitt_ctx *uitt_ctx)
{
	return refcount_read(&uitt_ctx->refs);
}

static void free_uitt_entry(struct uintr_uitt_ctx *uitt_ctx, unsigned int entry)
{
	if (WARN_ON_ONCE(entry >= UINTR_MAX_UITT_NR))
		return;

	pr_debug("send: Freeing UITTE entry %d for uitt_ctx=%lx\n",
		 entry, (unsigned long)uitt_ctx);

	put_upid_ref(uitt_ctx->r_upid_ctx[entry]);

	mutex_lock(&uitt_ctx->uitt_lock);
	memset(&uitt_ctx->uitt[entry], 0, sizeof(struct uintr_uitt_entry));
	mutex_unlock(&uitt_ctx->uitt_lock);

	clear_bit(entry, (unsigned long *)uitt_ctx->uitt_mask);

	if (is_uitt_empty(uitt_ctx)) {
		pr_debug("send: UITT mask is empty. UITT refcount=%d\n",
			 check_uitt_ref(uitt_ctx));
		/*
		 * Tearing down UITT is not simple. Multiple tasks would have
		 * their UITT MSR programmed. Instead of doing it right now
		 * delay the freeing to MM exit.
		 * TODO: Confirm uitt ref count is accurate.
		 */
		//teardown_uitt();
	}
}

/* TODO: Fix locking and atomicity of updates */
static void free_all_uitt_entries(struct uintr_uitt_ctx *uitt_ctx)
{
	int entry = find_first_bit((unsigned long *)uitt_ctx->uitt_mask,
				       UINTR_MAX_UITT_NR);

	while (entry != UINTR_MAX_UITT_NR) {
		free_uitt_entry(uitt_ctx, entry);
		entry = find_first_bit((unsigned long *)uitt_ctx->uitt_mask,
				       UINTR_MAX_UITT_NR);
	}
}

static void free_uitt(struct uintr_uitt_ctx *uitt_ctx)
{
	if (!is_uitt_empty(uitt_ctx)) {
		pr_debug("UITT: being freed but mask not empty\n");
		free_all_uitt_entries(uitt_ctx);
	}

	mutex_lock(&uitt_ctx->uitt_lock);

	kfree(uitt_ctx->uitt);
	uitt_ctx->uitt = NULL;
	mutex_unlock(&uitt_ctx->uitt_lock);

	kfree(uitt_ctx);
}

void put_uitt_ref(struct uintr_uitt_ctx *uitt_ctx)
{
	if (refcount_dec_and_test(&uitt_ctx->refs)) {
		pr_debug("UITT: %px Decrement refcount=0 Freeing UITT\n",
			 uitt_ctx->uitt);
		free_uitt(uitt_ctx);
	} else {
		pr_debug("UITT: %px Decrement refcount=%d\n",
			 uitt_ctx->uitt,
			 refcount_read(&uitt_ctx->refs));
	}
}

/* TODO: Confirm if this function is accurate */
void uintr_destroy_uitt_ctx(struct mm_struct *mm)
{
	if (mm->context.uitt_ctx) {
		pr_debug("mm exit: uitt ref: %d\n", check_uitt_ref(mm->context.uitt_ctx));
		put_uitt_ref(mm->context.uitt_ctx);
		//teardown_uitt(mm->context.uitt_ctx);
		mm->context.uitt_ctx = NULL;
	}
}

/* TODO: Replace UITT allocation with KPTI compatible memory allocator */
static struct uintr_uitt_ctx *alloc_uitt(void)
{
	struct uintr_uitt_ctx *uitt_ctx;
	struct uintr_uitt_entry *uitt;

	uitt_ctx = kzalloc(sizeof(*uitt_ctx), GFP_KERNEL);
	if (!uitt_ctx)
		return NULL;

	uitt = kzalloc(sizeof(*uitt) * UINTR_MAX_UITT_NR, GFP_KERNEL);
	if (!uitt) {
		kfree(uitt_ctx);
		return NULL;
	}

	uitt_ctx->uitt = uitt;
	mutex_init(&uitt_ctx->uitt_lock);
	refcount_set(&uitt_ctx->refs, 1);

	return uitt_ctx;
}

struct uintr_uitt_ctx *get_uitt_ref(struct uintr_uitt_ctx *uitt_ctx)
{
	refcount_inc(&uitt_ctx->refs);
	pr_debug("UITT: %px Increment refcount=%d\n",
		 uitt_ctx->uitt, refcount_read(&uitt_ctx->refs));

	return uitt_ctx;
}

static inline void mark_uitte_invalid(struct uintr_uitt_ctx *uitt_ctx, unsigned int uitt_index)
{
	struct uintr_uitt_entry *uitte;

	mutex_lock(&uitt_ctx->uitt_lock);
	uitte = &uitt_ctx->uitt[uitt_index];
	uitte->valid = 0;
	mutex_unlock(&uitt_ctx->uitt_lock);
}

static int init_uitt_ctx(void)
{
	struct mm_struct *mm = current->mm;
	struct uintr_uitt_ctx *uitt_ctx;

	uitt_ctx = alloc_uitt();
	if (!uitt_ctx) {
		pr_debug("send: Alloc UITT failed for task=%d\n", current->pid);
		return -ENOMEM;
	}

	pr_debug("send: Setup a new UITT=%px for mm=%lx with size %d\n",
		 uitt_ctx->uitt, (unsigned long)mm, UINTR_MAX_UITT_NR * 16);

	/* The UITT is allocated with a ref count of 1 */
	mm->context.uitt_ctx = uitt_ctx;

	return 0;
}

void uintr_set_sender_msrs(struct task_struct *t)
{
	struct uintr_uitt_ctx *uitt_ctx = t->mm->context.uitt_ctx;
	void *xstate;
	u64 msr64;

	/* Maybe WARN_ON_FPU */
	WARN_ON_ONCE(t != current);

	xstate = start_update_xsave_msrs(XFEATURE_UINTR);

	xsave_wrmsrl(xstate, MSR_IA32_UINTR_TT, (u64)uitt_ctx->uitt | 1);
	xsave_rdmsrl(xstate, MSR_IA32_UINTR_MISC, &msr64);
	msr64 &= GENMASK_ULL(63, 32);
	msr64 |= UINTR_MAX_UITT_NR - 1;
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_MISC, msr64);

	end_update_xsave_msrs();

	t->thread.uitt_activated = true;
}

bool uintr_check_uitte_valid(struct uintr_uitt_ctx *uitt_ctx, unsigned int entry)
{
	return !!test_bit(entry, (unsigned long *)uitt_ctx->uitt_mask);
}

/* TODO: Fix unregister flow. Also all modifications to the uitte should be under a single lock */
static int do_uintr_unregister_sender(struct uintr_uitt_ctx *uitt_ctx, unsigned int entry)
{
	/* Check if the supplied UITT index is valid */
	if (!uintr_check_uitte_valid(uitt_ctx, entry)) {
		pr_debug("send: Unregister for invalid UITTE %d for uitt_ctx=%lx\n",
			 entry, (unsigned long)uitt_ctx);
		return -EINVAL;
	}

	/* To make sure any new senduipi result in a #GP fault. */
	/*
	 * Check: Can the UITTE be modified directly. What is some other cpu
	 * (ucode) is concurrently accessing it?
	 */
	mark_uitte_invalid(uitt_ctx, entry);

	pr_debug("send: Freeing UITTE %d for uitt_ctx=%lx\n",
		 entry, (unsigned long)uitt_ctx);

	/*
	 * Check: Find a good way to free the uitte entry. Can we free the UITT
	 * directly instead of marking it invalid above?
	 */
	free_uitt_entry(uitt_ctx, entry);

	/* TODO: Verify UPID & UITT reference counting */
	//put_uitt_ref(uitt_ctx);

	return 0;
}

static int uintr_init_sender(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	int ret = 0;

	/* what about concurrency here? */
	if (!mm->context.uitt_ctx)
		ret = init_uitt_ctx();

	return ret;
}

/*
 * No lock is needed to read the active flag. Writes only happen from
 * r_info->task that owns the UPID. Everyone else would just read this flag.
 *
 * This only provides a static check. The receiver may become inactive right
 * after this check. The primary reason to have this check is to prevent future
 * senders from connecting with this UPID, since the receiver task has already
 * made this UPID inactive.
 */
static bool uintr_is_receiver_active(struct uintr_upid_ctx *upid_ctx)
{
	return upid_ctx->receiver_active;
}

static int do_uintr_register_sender(u64 uvec, struct uintr_upid_ctx *upid_ctx)
{
	struct uintr_uitt_entry *uitte = NULL;
	struct uintr_uitt_ctx *uitt_ctx;
	struct task_struct *t = current;
	int entry;
	int ret;

	/*
	 * Only a static check. Receiver could exit anytime after this check.
	 * This check only prevents connections using uvec_fd after the
	 * receiver has already exited/unregistered.
	 */
	if (!uintr_is_receiver_active(upid_ctx))
		return -ESHUTDOWN;

	ret = uintr_init_sender(t);
	if (ret)
		return ret;

	uitt_ctx = t->mm->context.uitt_ctx;

	BUILD_BUG_ON(UINTR_MAX_UITT_NR < 1);

	/* TODO: Need a lock to prevent concurrent access to uitt_mask */
	entry = find_first_zero_bit((unsigned long *)uitt_ctx->uitt_mask,
				    UINTR_MAX_UITT_NR);
	if (entry >= UINTR_MAX_UITT_NR)
		return -ENOSPC;

	set_bit(entry, (unsigned long *)uitt_ctx->uitt_mask);

	mutex_lock(&uitt_ctx->uitt_lock);

	uitte = &uitt_ctx->uitt[entry];
	pr_debug("send: sender=%d receiver=%d UITTE entry %d address %px\n",
		 t->pid, upid_ctx->task->pid, entry, uitte);

	/* Program the UITT entry */
	uitte->user_vec = uvec;
	uitte->target_upid_addr = (u64)upid_ctx->upid;
	uitte->valid = 1;

	uitt_ctx->r_upid_ctx[entry] = get_upid_ref(upid_ctx);

	mutex_unlock(&uitt_ctx->uitt_lock);

	//s_info->uitt_ctx = get_uitt_ref(uitt_ctx);
	//s_info->task = get_task_struct(current);
	//s_info->uitt_index = entry;

	if (!is_uintr_sender(t))
		uintr_set_sender_msrs(t);

	return entry;
}

static long uipifd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct uintr_uitt_ctx *uitt_ctx = file->private_data;
	struct task_struct *t = current;
	int ret = 0;

	switch (cmd) {
	case UIPI_SET_TARGET_TABLE:

		pr_debug("send: uipi fd SET TT IOCTL task=%d\n", t->pid);

		/*
		 * Clearing the UITT is a more involved procedure. The UITT
		 * could be in use across multiple processes.
		 */
		if (t->mm->context.uitt_ctx) {
			pr_debug("send: uitt_ctx is already set in mm for task=%d UITT=%px\n",
				 t->pid, t->mm->context.uitt_ctx->uitt);
			ret = -EBUSY;
			break;
		}

		t->mm->context.uitt_ctx = get_uitt_ref(uitt_ctx);

		/*
		 * Proactively set the sender MSRs for this task. This helps
		 * avoid the trap and instruction decode
		 */
		uintr_set_sender_msrs(t);

		pr_debug("send: uitt_ctx is being set in mm for task=%d UITT=%px\n",
			 t->pid, uitt_ctx->uitt);
		break;

#if 0
	case UIPI_CLEAR_TARGET_TABLE:

		/*
		 * Clearing the UITT is a more involved procedure. The UITT
		 * could be in use across multiple processes.
		 */
		ret = -EOPNOTSUPP;
		pr_debug("send: uipi fd CLEAR TT IOCTL is not supported task=%d\n",
			 t->pid);
		break;
#endif

	default:
		pr_debug("send: Invalid uipi_fd IOCTL command %d\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static int uipifd_release(struct inode *inode, struct file *file)
{
	struct uintr_uitt_ctx *uitt_ctx = file->private_data;

	pr_debug("send: Releasing uipi fd for task=%d UITT=%px\n",
		 current->pid, uitt_ctx->uitt);

	/* UITT stays allocated until the process dies, no need to clear mm */

	put_uitt_ref(uitt_ctx);

	return 0;
}

static int uipifd_open(struct inode *inode, struct file *file)
{
	struct task_struct *t = current;
	struct uintr_uitt_ctx *uitt_ctx;

	pr_debug("send: uipi fd opened task=%d\n", current->pid);

	uitt_ctx = t->mm->context.uitt_ctx;
	/* TODO: Figure out how the ordering works in this case */
	if (!uitt_ctx) {
		uitt_ctx = file->private_data;
		t->mm->context.uitt_ctx = uitt_ctx;
		pr_debug("send: uitt_ctx is being set in mm for task=%d UITT=%px\n",
			 current->pid, uitt_ctx->uitt);
	} else {
		pr_debug("send: uitt_ctx already set in mm for task=%d UITT=%px\n",
			 current->pid, uitt_ctx->uitt);
	}

	return 0;
}

static const struct file_operations uipifd_fops = {
#ifdef CONFIG_PROC_FS
	//.show_fdinfo	= uipifd_show_fdinfo,
#endif
	.unlocked_ioctl = uipifd_ioctl,
	.open		= uipifd_open,
	.release	= uipifd_release,
	.llseek		= noop_llseek,
};

/*
 * sys_uintr_ipi_fd - Create a uipi_fd to execute SENDUIPI.
 */
SYSCALL_DEFINE1(uintr_ipi_fd, unsigned int, flags)
{
	struct uintr_uitt_ctx *uitt_ctx;
	int uipi_fd;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	ret = uintr_init_sender(current);
	if (ret)
		return ret;

	uitt_ctx = get_uitt_ref(current->mm->context.uitt_ctx);

	/* TODO: Get user input for flags - UFD_CLOEXEC? */
	/* Check: Do we need O_NONBLOCK? */
	uipi_fd = anon_inode_getfd("[uipi_fd]", &uipifd_fops, uitt_ctx,
				   O_RDONLY | O_CLOEXEC | O_NONBLOCK);

	if (uipi_fd < 0) {
		put_uitt_ref(uitt_ctx);
		pr_debug("send: uipi_fd create failed for task=%d ret %d\n",
			 current->pid, ret);
	} else {
		pr_debug("send: Alloc success uipi_fd %d for task=%d\n",
			 uipi_fd, current->pid);
	}

	return uipi_fd;
}

/*
 * sys_uintr_register_sender - setup user inter-processor interrupt sender.
 */
SYSCALL_DEFINE2(uintr_register_sender, int, uvecfd, unsigned int, flags)
{
	//struct uintr_uitt_ctx *uitt_ctx;
	//struct uintr_sender_info *s_info;
	struct uvecfd_ctx *uvecfd_ctx;
	//unsigned long lock_flags;
	struct file *uvec_f;
	struct fd f;
	int ret = 0;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	f = fdget(uvecfd);
	uvec_f = f.file;
	if (!uvec_f)
		return -EBADF;

	if (uvec_f->f_op != &uvecfd_fops) {
		ret = -EOPNOTSUPP;
		goto out_fdput;
	}

	uvecfd_ctx = (struct uvecfd_ctx *)uvec_f->private_data;

	/*
	 * We would need to store the sender list in order to detect if a
	 * connection has already been made. Also care must taken to
	 * incorporate concurrent modifications to the uitt_ctx
	 */
#if 0
	uitt_ctx = current->mm->context.uitt_ctx;

	/* Detect if a connection has already been made */
	if (uitt_ctx) {
		spin_lock_irqsave(&uvecfd_ctx->sender_lock, lock_flags);
		list_for_each_entry(s_info, &uvecfd_ctx->sender_list, node) {
			if (s_info->uitt_ctx == uitt_ctx) {
				ret = -EISCONN;
				break;
			}
		}
		spin_unlock_irqrestore(&uvecfd_ctx->sender_lock, lock_flags);

		if (ret)
			goto out_fdput;
	}

	s_info = kzalloc(sizeof(*s_info), GFP_KERNEL);
	if (!s_info) {
		ret = -ENOMEM;
		goto out_fdput;
	}
#endif

	ret = do_uintr_register_sender(uvecfd_ctx->uvec, uvecfd_ctx->upid_ctx);
	if (ret < 0) {
		//kfree(s_info);
		goto out_fdput;
	}

	//spin_lock_irqsave(&uvecfd_ctx->sender_lock, lock_flags);
	//list_add(&s_info->node, &uvecfd_ctx->sender_list);
	//spin_unlock_irqrestore(&uvecfd_ctx->sender_lock, lock_flags);

	//ret = s_info->uitt_index;

out_fdput:
	pr_debug("send: register sender task=%d flags %d ret(uipi_id)=%d\n",
		 current->pid, flags, ret);

	fdput(f);
	return ret;
}

/*
 * sys_uintr_unregister_sender - Unregister user inter-processor interrupt sender.
 */
SYSCALL_DEFINE2(uintr_unregister_sender, int, uipi_index, unsigned int, flags)
{
	struct uintr_uitt_ctx *uitt_ctx;
	struct fd f;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	uitt_ctx = current->mm->context.uitt_ctx;
	if (!uitt_ctx) {
		pr_debug("send: unregister sender for task=%d, something might be wrong here\n",
			 current->pid);
		ret = -EINVAL;
		goto out_fdput;
	}

	ret = do_uintr_unregister_sender(uitt_ctx, uipi_index);

	pr_debug("send: unregister sender uipi_index %d for task=%d ret %d\n",
		 uipi_index, current->pid, ret);

out_fdput:
	fdput(f);
	return ret;
}

/*
 * sys_uintr_register_self - Register self as UINTR sender (without creating an FD)
 */
SYSCALL_DEFINE2(uintr_register_self, u64, vector, unsigned int, flags)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	/* Pass NULL since no FD is being created */
	ret = do_uintr_register_vector(vector, NULL);
	if (ret)
		return ret;

	ret = do_uintr_register_sender(vector, current->thread.upid_ctx);
	if (ret < 0)
		do_uintr_unregister_vector(vector, current->thread.upid_ctx);

	return ret;
}

static inline void set_uintr_waiting(struct task_struct *t)
{
	t->thread.upid_ctx->waiting = true;
}

static int do_uintr_unregister_handler(void)
{
	struct task_struct *t = current;
	struct uintr_upid_ctx *upid_ctx;
	void *xstate;
	u64 msr64;

	if (!is_uintr_receiver(t))
		return -EINVAL;

	pr_debug("recv: Unregister handler and clear MSRs for task=%d\n",
		 t->pid);

	/*
	 * UPID and upid_activated will be referenced during context switch. Need to
	 * disable preemption while modifying the MSRs, UPID and ui_recv thread
	 * struct.
	 */
	xstate = start_update_xsave_msrs(XFEATURE_UINTR);

	xsave_rdmsrl(xstate, MSR_IA32_UINTR_MISC, &msr64);
	msr64 &= ~GENMASK_ULL(39, 32);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_MISC, msr64);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_PD, 0);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_RR, 0);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_STACKADJUST, 0);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_HANDLER, 0);

	upid_ctx = t->thread.upid_ctx;
	//upid_ctx->receiver_active = false;

	t->thread.upid_activated = false;

	/*
	 * Suppress notifications so that no further interrupts are generated
	 * based on this UPID.
	 */
	set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid_ctx->upid->nc.status);

	/* Release reference since the removed it from the MSR. */
	put_upid_ref(upid_ctx);

	uintr_remove_task_wait(t);

	end_update_xsave_msrs();

	/*
	 * Once a UPID and thread struct are allocated for a thread, they will
	 * always stay allocated. This makes it easy to handle concurrency when
	 * allocating and freeing vectors. And to avoid failures on the sender
	 * when the receiver unregisters
	 */

	/*
	 * TODO: Figure out what do we do with existing connections (in the
	 * UITT) that have been made with this UPID
	 */
	/* Below would happen only during receiver exit */
	//kfree(ui_recv);
	//t->thread.ui_recv = NULL;

	return 0;
}

static inline u32 cpu_to_ndst(int cpu)
{
	u32 apicid = (u32)apic->cpu_present_to_apicid(cpu);

	WARN_ON_ONCE(apicid == BAD_APICID);

	if (!x2apic_enabled())
		return (apicid << 8) & 0xFF00;

	return apicid;
}

static int do_uintr_register_handler(u64 handler, unsigned int flags)
{
	struct uintr_upid_ctx *upid_ctx;
	struct uintr_upid *upid;
	struct task_struct *t = current;
	void *xstate;
	u64 misc_msr;
	int cpu;

	if (is_uintr_receiver(t))
		return -EBUSY;

	/*
	 * Once a UPID context is allocated for a thread, it will always stay
	 * allocated. This makes it easy to handle concurrency when allocating
	 * and freeing vectors. And to avoid failures on the sender when the
	 * receiver unregisters
	 */

	upid_ctx = t->thread.upid_ctx;

	/* The thread struct might have been allocated from the previous registration.  */
	if (!upid_ctx) {
		upid_ctx = alloc_upid();
		if (!upid_ctx)
			return -ENOMEM;
		t->thread.upid_ctx = upid_ctx;
	}

	/*
	 * UPID and upid_activated will be referenced during context switch. Need to
	 * disable preemption while modifying the MSRs, UPID and upid_activated
	 * struct.
	 */
	xstate = start_update_xsave_msrs(XFEATURE_UINTR);

	cpu = smp_processor_id();

	/* Take another reference to the UPID since it is being programmed in the MSR */
	get_upid_ref(upid_ctx);

	/* Check if a locked access is needed for NV and NDST bits of the UPID */
	upid = upid_ctx->upid;
	upid->nc.nv = UINTR_NOTIFICATION_VECTOR;
	upid->nc.ndst = cpu_to_ndst(cpu);

	xsave_wrmsrl(xstate, MSR_IA32_UINTR_HANDLER, handler);

	xsave_wrmsrl(xstate, MSR_IA32_UINTR_PD, (u64)upid);

	/* Set value as size of ABI redzone */
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_STACKADJUST, OS_ABI_REDZONE);

	/* Modify only the relevant bits of the MISC MSR */
	xsave_rdmsrl(xstate, MSR_IA32_UINTR_MISC, &misc_msr);
	misc_msr |= (u64)UINTR_NOTIFICATION_VECTOR << 32;
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_MISC, misc_msr);

	t->thread.upid_activated = true;

	end_update_xsave_msrs();

	if (flags & UINTR_HANDLER_FLAG_WAITING_ANY) {
		if (flags & UINTR_HANDLER_FLAG_WAITING_RECEIVER)
			upid_ctx->waiting_cost = UPID_WAITING_COST_RECEIVER;
		else
			upid_ctx->waiting_cost = UPID_WAITING_COST_SENDER;
	}

	pr_debug("recv: task=%d register handler=%llx upid %px flags=%d\n",
		 t->pid, handler, upid, flags);

	return 0;
}

/*
 * sys_uintr_register_handler - setup user interrupt handler for receiver.
 */
SYSCALL_DEFINE2(uintr_register_handler, u64 __user *, handler, unsigned int, flags)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	pr_debug("recv: requesting register handler task=%d flags %d handler %lx\n",
		 current->pid, flags, (unsigned long)handler);

	if (flags & ~UINTR_HANDLER_FLAG_WAITING_ANY)
		return -EINVAL;

	if (flags && !IS_ENABLED(CONFIG_X86_UINTR_BLOCKING))
		return -EINVAL;

	/* TODO: Validate the handler address */
	if (!handler)
		return -EFAULT;

	ret = do_uintr_register_handler((u64)handler, flags);

	pr_debug("recv: register handler task=%d flags %d handler %lx ret %d\n",
		 current->pid, flags, (unsigned long)handler, ret);

	return ret;
}

/*
 * sys_uintr_unregister_handler - Teardown user interrupt handler for receiver.
 */
SYSCALL_DEFINE1(uintr_unregister_handler, unsigned int, flags)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	ret = do_uintr_unregister_handler();

	pr_debug("recv: unregister handler task=%d flags %d ret %d\n",
		 current->pid, flags, ret);

	return ret;
}

static int do_uintr_alt_stack(void __user *sp, size_t size)
{
	struct task_struct *t = current;
	void *xstate;
	u64 msr64;

	/*
	 * For now, alternate stack should only be registered by a task that
	 * has an interrupt handler already registered.
	 *
	 * Unregistering the interrupt handler will also clear the alternate stack.
	 */
	if (!is_uintr_receiver(t))
		return -EOPNOTSUPP;

	/* Check: if the stack size needs to be aligned? */

	if (sp)
		msr64 = (u64)sp | 1; //set alt stack
	else
		msr64 = OS_ABI_REDZONE; //program OS_ABI_REDZONE

	xstate = start_update_xsave_msrs(XFEATURE_UINTR);
	xsave_wrmsrl(xstate, MSR_IA32_UINTR_STACKADJUST, msr64);
	end_update_xsave_msrs();

	return 0;
}

/*
 * sys_uintr_alt_stack - Set an alternate stack for UINTR handling
 */
SYSCALL_DEFINE3(uintr_alt_stack, void __user *, sp, size_t, size, unsigned int, flags)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	/* Check: Would it be helpful to have a common stack struct between signals and UINTR */

	/* TODO: Validate address and size */

	ret = do_uintr_alt_stack(sp, size);

	pr_debug("recv: atl stack task=%d sp: %llx size: %ld ret: %d\n",
		 current->pid, (u64)sp, size, ret);

	return ret;
}

#if 0
/* For notify receiver */
/* TODO: Find a more efficient way rather than iterating over each cpu */
static int convert_apicid_to_cpu(int apic_id)
{
	int i;

	for_each_possible_cpu(i) {
		if (per_cpu(x86_cpu_to_apicid, i) == apic_id)
			return i;
	}
	return -1;
}

static inline int ndst_to_cpu(u32 ndst)
{
	int apic_id;
	int cpu;

	if (!x2apic_enabled())
		apic_id = (ndst >> 8) & 0xFF;
	else
		apic_id = ndst;

	cpu = convert_apicid_to_cpu(apic_id);

	WARN_ON_ONCE(cpu == -1);

	pr_debug("uintr: converted ndst %x to cpu %d\n", ndst, cpu);
	return cpu;
}
#endif

static int uintr_notify_receiver(u64 uvec, struct uintr_upid_ctx *upid_ctx)
{
	//struct uintr_upid_ctx *upid_ctx = upid_ctx;
	struct uintr_upid *upid = upid_ctx->upid;

	set_bit((unsigned long)uvec, (unsigned long *)&upid->puir);

	pr_debug("notify: Posted vector %llu to task %d\n",
		 uvec, upid_ctx->task->pid);

	pr_debug("notify: puir=%llx SN %x ON %x NDST %x NV %x",
		 upid->puir, test_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid->nc.status),
		 test_bit(UINTR_UPID_STATUS_ON, (unsigned long *)&upid->nc.status),
		 upid->nc.ndst, upid->nc.nv);

	/* TODO: Use cmpxchg for UPID since we are doing read-modify-write */
	if (!test_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid->nc.status) &&
	    !test_and_set_bit(UINTR_UPID_STATUS_ON, (unsigned long *)&upid->nc.status)) {

		pr_debug("notify: Sending IPI to NDST %x with NV %x\n",
			 upid->nc.ndst, upid->nc.nv);

		/*
		 * Confirm: Which method is more efficient?
		 *	1. Directly program the APIC as done below
		 *	2. Convert ndst to cpu and then use send_IPI()
		 */
		apic->send_UINTR(upid->nc.ndst, upid->nc.nv);

	} else {
		pr_debug("notify: Skip sending IPI to task %d\n",
			 upid_ctx->task->pid);
	}

	return 0;
}

/**
 * uintr_notify - Notify a user interrupt receiver.
 * @uvec_f: [in] File pertaining to the uvec_fd.
 *
 * Returns <tbd>
 */
int uintr_notify(struct file *uvec_f)
{
	struct uvecfd_ctx *uvecfd_ctx;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -EINVAL;

	if (uvec_f->f_op != &uvecfd_fops)
		return -EINVAL;

	uvecfd_ctx = (struct uvecfd_ctx *)uvec_f->private_data;

	return uintr_notify_receiver(uvecfd_ctx->uvec, uvecfd_ctx->upid_ctx);
}
EXPORT_SYMBOL_GPL(uintr_notify);

/**
 * uvecfd_fget - Acquire a reference of an uvecfd file descriptor.
 * @fd: [in] uvecfd file descriptor.
 *
 * Returns a pointer to the uvecfd file structure in case of success, or the
 * following error pointer:
 *
 * -EBADF    : Invalid @fd file descriptor.
 * -EINVAL   : The @fd file descriptor is not an uvecfd file.
 */
struct file *uvecfd_fget(int fd)
{
	struct file *file;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return ERR_PTR(-EINVAL);

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &uvecfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}
EXPORT_SYMBOL_GPL(uvecfd_fget);

static int uintr_receiver_wait(ktime_t *expires)
{
	struct task_struct *tsk = current;
	struct hrtimer_sleeper t;

	if (!is_uintr_receiver(tsk))
		return -EOPNOTSUPP;

	pr_debug("uintr: Pause for uintr for task %d\n", tsk->pid);

	// uintr_switch_to_kernel_interrupt(tsk);

	hrtimer_init_sleeper_on_stack(&t, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_set_expires_range_ns(&t.timer, *expires, 0);
	hrtimer_sleeper_start_expires(&t, HRTIMER_MODE_REL);

	set_current_state(TASK_INTERRUPTIBLE);

	if (t.task)
		schedule();

	hrtimer_cancel(&t.timer);
	destroy_hrtimer_on_stack(&t.timer);

	//if (!t.task)
	//	uintr_remove_task_wait(tsk);

	__set_current_state(TASK_RUNNING);

	pr_debug("recv: Returned from schedule task=%d\n",
		 current->pid);

	return !t.task ? 0 : -EINTR;
}

/* For now, use a max value of 1000 seconds */
#define UINTR_WAIT_MAX_USEC	1000000000

/*
 * sys_uintr_wait - Wait for a user interrupt for the specified time
 */
SYSCALL_DEFINE2(uintr_wait, u64, usec, unsigned int, flags)
{
	ktime_t expires;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return -ENOSYS;

	if (!IS_ENABLED(CONFIG_X86_UINTR_BLOCKING))
		return -ENOSYS;

	if (flags)
		return -EINVAL;

	/* Check: Do we need an option for waiting indefinitely */
	if (usec > UINTR_WAIT_MAX_USEC)
		return -EINVAL;

	if (usec == 0)
		return 0;

	expires = usec * NSEC_PER_USEC;
	return uintr_receiver_wait(&expires);
}

static void uintr_switch_to_kernel_interrupt(struct uintr_upid_ctx *upid_ctx)
{
	unsigned long flags;

	upid_ctx->upid->nc.nv = UINTR_KERNEL_VECTOR;
	upid_ctx->waiting = true;
	spin_lock_irqsave(&uintr_wait_lock, flags);
	list_add(&upid_ctx->node, &uintr_wait_list);
	spin_unlock_irqrestore(&uintr_wait_lock, flags);
}

static void uintr_set_blocked_upid_bit(struct uintr_upid_ctx *upid_ctx)
{
	set_bit(UINTR_UPID_STATUS_BLKD, (unsigned long *)&upid_ctx->upid->nc.status);
	upid_ctx->waiting = true;
}

static inline bool is_uintr_waiting_cost_sender(struct task_struct *t)
{
	return (t->thread.upid_ctx->waiting_cost == UPID_WAITING_COST_SENDER);
}

static inline bool is_uintr_waiting_enabled(struct task_struct *t)
{
	return (t->thread.upid_ctx->waiting_cost != UPID_WAITING_COST_NONE);
}

/* Suppress notifications since this task is being context switched out */
void switch_uintr_prepare(struct task_struct *prev)
{
	struct uintr_upid_ctx *upid_ctx;

	if (!is_uintr_receiver(prev))
		return;

	/* Check if UIF should be considered here. Do we want to wait for interrupts if UIF is 0? */
	upid_ctx = prev->thread.upid_ctx;

	/*
	 * A task being interruptible is a dynamic state. Need synchronization
	 * in schedule() along with singal_pending_state() to avoid blocking if
	 * a UINTR is pending
	 */
	if (IS_ENABLED(CONFIG_X86_UINTR_BLOCKING) &&
	    is_uintr_waiting_enabled(prev) &&
	    task_is_interruptible(prev)) {
		if (!is_uintr_waiting_cost_sender(prev)) {
			uintr_switch_to_kernel_interrupt(upid_ctx);
			return;
		}

		uintr_set_blocked_upid_bit(upid_ctx);
	}

	set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid_ctx->upid->nc.status);
}

/*
 * Do this right before we are going back to userspace after the FPU has been
 * reloaded i.e. TIF_NEED_FPU_LOAD is clear.
 * Called from arch_exit_to_user_mode_prepare() with interrupts disabled.
 */
void switch_uintr_return(void)
{
	struct uintr_upid *upid;
	u64 misc_msr;

	if (!is_uintr_receiver(current))
		return;

	/*
	 * The XSAVES instruction clears the UINTR notification vector(UINV) in
	 * the UINT_MISC MSR when user context gets saved. Before going back to
	 * userspace we need to restore the notification vector. XRSTORS would
	 * automatically restore the notification but we can't be sure that
	 * XRSTORS will always be called when going back to userspace. Also if
	 * XSAVES gets called twice the UINV stored in the Xstate buffer will
	 * be overwritten. Threfore, before going back to userspace we always
	 * check if the UINV is set and reprogram if needed.
	 *
	 * Alternatively, we could combine this with switch_fpu_return() and
	 * program the MSR whenever we are skipping the XRSTORS. We need
	 * special precaution to make sure the UINV value in the XSTATE buffer
	 * doesn't get overwritten by calling XSAVES twice.
	 */
	WARN_ON_ONCE(test_thread_flag(TIF_NEED_FPU_LOAD));

	/* Modify only the relevant bits of the MISC MSR */
	rdmsrl(MSR_IA32_UINTR_MISC, misc_msr);
	if (!(misc_msr & GENMASK_ULL(39, 32))) {
		misc_msr |= (u64)UINTR_NOTIFICATION_VECTOR << 32;
		wrmsrl(MSR_IA32_UINTR_MISC, misc_msr);
	}

	/*
	 * It is necessary to clear the SN bit after we set UINV and NDST to
	 * avoid incorrect interrupt routing.
	 */
	upid = current->thread.upid_ctx->upid;
	upid->nc.ndst = cpu_to_ndst(smp_processor_id());
	clear_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid->nc.status);

	/*
	 * Interrupts might have accumulated in the UPID while the thread was
	 * preempted. In this case invoke the hardware detection sequence
	 * manually by sending a self IPI with UINV.  Since UINV is set and SN
	 * is cleared, any new UINTR notifications due to the self IPI or
	 * otherwise would result in the hardware updating the UIRR directly.
	 * No real interrupt would be generated as a result of this.
	 *
	 * The alternative is to atomically read and clear the UPID and program
	 * the UIRR. In that case the kernel would need to carefully manage the
	 * race with the hardware if the UPID gets updated after the read.
	 */
	if (READ_ONCE(upid->puir))
		apic->send_IPI_self(UINTR_NOTIFICATION_VECTOR);
}

/* Check does SN need to be set here */
/* Called when task is unregistering/exiting or timer expired */
static void uintr_remove_task_wait(struct task_struct *task)
{
	struct uintr_upid_ctx *upid_ctx, *tmp;
	unsigned long flags;

	if (!IS_ENABLED(CONFIG_X86_UINTR_BLOCKING))
		return;

	spin_lock_irqsave(&uintr_wait_lock, flags);
	list_for_each_entry_safe(upid_ctx, tmp, &uintr_wait_list, node) {
		if (upid_ctx->task == task) {
			//pr_debug("wait: Removing task %d from wait\n",
			//	 upid_ctx->task->pid);
			upid_ctx->upid->nc.nv = UINTR_NOTIFICATION_VECTOR;
			upid_ctx->waiting = false;
			list_del(&upid_ctx->node);
		}
	}
	spin_unlock_irqrestore(&uintr_wait_lock, flags);
}

static void uintr_clear_blocked_bit(struct uintr_upid_ctx *upid_ctx)
{
	upid_ctx->waiting = false;
	clear_bit(UINTR_UPID_STATUS_BLKD, (unsigned long *)&upid_ctx->upid->nc.status);
}

/* Always make sure task is_uintr_receiver() before calling */
static inline bool is_uintr_waiting(struct task_struct *t)
{
	return t->thread.upid_ctx->waiting;
}

void switch_uintr_finish(struct task_struct *next)
{
	if (IS_ENABLED(CONFIG_X86_UINTR_BLOCKING) &&
	    is_uintr_receiver(next) &&
	    is_uintr_waiting(next)) {
		if (is_uintr_waiting_cost_sender(next))
			uintr_clear_blocked_bit(next->thread.upid_ctx);
		else
			uintr_remove_task_wait(next);
	}
}

/*
 * This should only be called from exit_thread().
 * exit_thread() can happen in current context when the current thread is
 * exiting or it can happen for a new thread that is being created.
 * For new threads is_uintr_task() will fail.
 */
void uintr_free(struct task_struct *t)
{
	struct uintr_upid_ctx *upid_ctx;
	void *xstate;

	if (!cpu_feature_enabled(X86_FEATURE_UINTR))
		return;

	upid_ctx = t->thread.upid_ctx;
	if (is_uintr_task(t)) {
		xstate = start_update_xsave_msrs(XFEATURE_UINTR);

		xsave_wrmsrl(xstate, MSR_IA32_UINTR_MISC, 0);
		xsave_wrmsrl(xstate, MSR_IA32_UINTR_TT, 0);
		xsave_wrmsrl(xstate, MSR_IA32_UINTR_PD, 0);
		xsave_wrmsrl(xstate, MSR_IA32_UINTR_RR, 0);
		xsave_wrmsrl(xstate, MSR_IA32_UINTR_STACKADJUST, 0);
		xsave_wrmsrl(xstate, MSR_IA32_UINTR_HANDLER, 0);

		/* If upid is active, upid_ctx will be valid */
		if (is_uintr_receiver(t)) {
			/*
			 * Suppress notifications so that no further interrupts are
			 * generated based on this UPID.
			 */
			set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid_ctx->upid->nc.status);
			uintr_remove_task_wait(t);
			upid_ctx->receiver_active = false;
			put_upid_ref(upid_ctx);
		}

		t->thread.upid_activated = false;
		t->thread.uitt_activated = false;

		end_update_xsave_msrs();
	}

	if (upid_ctx) {
		put_upid_ref(t->thread.upid_ctx);
		/*
		 * This might not be needed since the thread is exiting. Have
		 * it anyways to be safe.
		 */
		t->thread.upid_ctx = NULL;
	}

	//if (WARN_ON_ONCE(t != current))
	//	return;
#if 0
	/* TODO: Fix exit flow */
	if (is_uintr_sender(t)) {
		/* TODO: Fix UITT dereferencing */
		//put_uitt_ref(t->thread.ui_send->uitt_ctx);
		//kfree(t->thread.ui_send);
		t->thread.uitt_activated = false;
	}
#endif
}

/*
 * Runs in interrupt context.
 * Scan through all UPIDs to check if any interrupt is on going.
 */
void uintr_wake_up_process(void)
{
	struct uintr_upid_ctx *upid_ctx, *tmp;
	unsigned long flags;

	/* Fix: 'BUG: Invalid wait context' due to use of spin lock here */
	spin_lock_irqsave(&uintr_wait_lock, flags);
	list_for_each_entry_safe(upid_ctx, tmp, &uintr_wait_list, node) {
		if (test_bit(UINTR_UPID_STATUS_ON, (unsigned long *)&upid_ctx->upid->nc.status)) {
			pr_debug_ratelimited("uintr: Waking up task %d\n",
					     upid_ctx->task->pid);
			set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&upid_ctx->upid->nc.status);
			/* Check if a locked access is needed for NV and NDST bits of the UPID */
			upid_ctx->upid->nc.nv = UINTR_NOTIFICATION_VECTOR;
			upid_ctx->waiting = false;
			set_tsk_thread_flag(upid_ctx->task, TIF_NOTIFY_SIGNAL);
			wake_up_process(upid_ctx->task);
			list_del(&upid_ctx->node);
		}
	}
	spin_unlock_irqrestore(&uintr_wait_lock, flags);
}
