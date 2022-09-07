// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Intel Corporation.
 *
 * Sohil Mehta <sohil.mehta@intel.com>
 * Jacob Pan <jacob.jun.pan@linux.intel.com>
 */
#define pr_fmt(fmt)    "uintr: " fmt

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

#define OS_ABI_REDZONE 128

inline bool is_uintr_receiver(struct task_struct *t)
{
	return !!t->thread.upid_activated;
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

	return upid_ctx;
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

	if (flags)
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

/* Suppress notifications since this task is being context switched out */
void switch_uintr_prepare(struct task_struct *prev)
{
	struct uintr_upid_ctx *upid_ctx;

	if (!is_uintr_receiver(prev))
		return;

	/* Check if UIF should be considered here. Do we want to wait for interrupts if UIF is 0? */
	upid_ctx = prev->thread.upid_ctx;

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
