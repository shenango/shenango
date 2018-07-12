/*
 * ksched.c - an accelerated scheduler interface for the IOKernel
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/smp.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/mwait.h>

#include "ksched.h"

MODULE_LICENSE("GPL");

/* the character device that provides the ksched IOCTL interface */
static struct cdev ksched_cdev;

struct ksched_percpu {
	unsigned long	gen;
	unsigned long	last_gen;
	pid_t		prev_pid;
	pid_t		next_pid;
} ____cacheline_aligned_in_smp;

/* per-cpu data shared between parked cores and the waker core */
static DEFINE_PER_CPU(struct ksched_percpu, kp);

/**
 * ksched_lookup_task - retreives a task from a pid number
 * @nr: the pid number
 *
 * WARNING: must be called inside an RCU read critical section.
 *
 * Returns a task pointer or NULL if none was found.
 */
static struct task_struct *ksched_lookup_task(pid_t nr)
{
	return pid_task(find_vpid(nr), PIDTYPE_PID);
}

static int ksched_wakeup_pid(int cpu, pid_t pid)
{
	struct task_struct *p;
	int ret;

	rcu_read_lock();
	p = ksched_lookup_task(pid);
	if (!p) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(p);
	rcu_read_unlock();

	ret = set_cpus_allowed_ptr(p, cpumask_of(cpu));
	if (ret) {
		put_task_struct(p);
		return ret;
	}

	wake_up_process(p);
	put_task_struct(p);

	return 0;
}

static long ksched_park(void)
{
	struct ksched_percpu *p;
	unsigned long gen;
	pid_t pid;
	int cpu;

	cpu = get_cpu();
	p = this_cpu_ptr(&kp);

	local_irq_disable();
	if (unlikely(signal_pending(current))) {
		local_irq_enable();
		put_cpu();
		return -ERESTARTSYS;
	}

	while (true) {
		/* first see if the condition is met without waiting */
		gen = smp_load_acquire(&p->gen);
		if (gen != p->last_gen)
			break;

		/* then arm the monitor address and recheck to avoid a race */
		__monitor(&p->gen, 0, 0);
		gen = smp_load_acquire(&p->gen);
		if (gen != p->last_gen)
			break;

		/* finally, execute mwait, and recheck after waking up */
		__mwait(0, MWAIT_ECX_INTERRUPT_BREAK);
		gen = smp_load_acquire(&p->gen);
		if (gen != p->last_gen)
			break;

		/* we woke up for some reason other than our condition */
		local_irq_enable();
		if (unlikely(signal_pending(current))) {
			put_cpu();
			return -ERESTARTSYS;
		}
		put_cpu();

		/* run another task if needed */
		if (need_resched())
			schedule();

		cpu = get_cpu();
		p = this_cpu_ptr(&kp);
		local_irq_disable();
	}

	/* the pid was set before the generation number (x86 is TSO) */
	pid = READ_ONCE(p->next_pid);
	p->last_gen = gen;
	local_irq_enable();

	/* are we waking the current pid? */
	if (pid == current->pid) {
		put_cpu();
		return 0;
	}
	ksched_wakeup_pid(cpu, pid);
	put_cpu();

	/* put this task to sleep and reschedule so the next task can run */
	__set_current_state(TASK_INTERRUPTIBLE);
	schedule();
	__set_current_state(TASK_RUNNING);
	return 0;
}

static long ksched_start(void)
{
	/* put this task to sleep and reschedule so the next task can run */
	__set_current_state(TASK_INTERRUPTIBLE);
	schedule();
	__set_current_state(TASK_RUNNING);
	return 0;
}

static void ksched_ipi(void *unused)
{
	struct ksched_percpu *p = this_cpu_ptr(&kp);
	struct task_struct *t;
	unsigned long gen;


	/* if last_gen is the current gen, ksched_park() beat us here */
	gen = smp_load_acquire(&p->gen);
	if (gen == p->last_gen)
		return;

	if (!p->prev_pid) {
		/* wake up the next pid */
		ksched_wakeup_pid(smp_processor_id(), p->next_pid);
	} else {
		/* otherwise send a signal to the old pid */ 
		rcu_read_lock();
		t = ksched_lookup_task(p->prev_pid);
		if (!t) {
			rcu_read_unlock();
			return;
		}
		send_sig(SIGUSR1, t, 0);
		rcu_read_unlock();
	}
}

static long ksched_wake(struct ksched_wake_req __user *req)
{
	static unsigned long gen = 0;
	struct ksched_wakeup wakeup;
	struct ksched_percpu *p;
	cpumask_var_t mask;
	unsigned int nr;
	int ret, i;

	/* validate inputs */
	ret = copy_from_user(&nr, &req->nr, sizeof(nr));
	if (unlikely(ret))
		return ret;
	if (unlikely(!alloc_cpumask_var(&mask, GFP_KERNEL)))
		return -ENOMEM;
	cpumask_clear(mask);

	gen++;
	for (i = 0; i < nr; i++) {
		ret = copy_from_user(&wakeup, &req->wakeups[i],
				     sizeof(wakeup));
		if (unlikely(ret)) {
			free_cpumask_var(mask);
			return ret;
		}
		if (unlikely(!cpu_possible(wakeup.cpu))) {
			free_cpumask_var(mask);
			return -EINVAL;
		}

		p = per_cpu_ptr(&kp, wakeup.cpu);
		p->prev_pid = wakeup.prev_tid;
		p->next_pid = wakeup.next_tid;
		smp_store_release(&p->gen, gen);
		if (wakeup.preempt)
			cpumask_set_cpu(wakeup.cpu, mask);
	}

	if (!cpumask_empty(mask))
		smp_call_function_many(mask, ksched_ipi, NULL, false);
	free_cpumask_var(mask);
	return 0;
}

static long
ksched_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* validate input */
	if (unlikely(_IOC_TYPE(cmd) != KSCHED_MAGIC))
		return -ENOTTY;
	if (unlikely(_IOC_NR(cmd) > KSCHED_IOC_MAXNR))
		return -ENOTTY;

	switch (cmd) {
	case KSCHED_IOC_PARK:
		return ksched_park();
	case KSCHED_IOC_START:
		return ksched_start();
	case KSCHED_IOC_WAKE:
		return ksched_wake((void __user *)arg);
	default:
		break;
	}

	return -ENOTTY;
}

static int ksched_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int ksched_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static struct file_operations ksched_ops = {
	.owner =	THIS_MODULE,
	.unlocked_ioctl = ksched_ioctl,
	.open =		ksched_open,
	.release =	ksched_release,
};

static int __init ksched_init(void)
{
	dev_t devno = MKDEV(KSCHED_MAJOR, KSCHED_MINOR);
	int ret;

	ret = register_chrdev_region(devno, 1, "ksched");
	if (ret) {
		printk(KERN_ERR "ksched: failed to reserve char dev region\n");
		return ret;
	}

	cdev_init(&ksched_cdev, &ksched_ops);
	ret = cdev_add(&ksched_cdev, devno, 1);
	if (ret) {
		printk(KERN_ERR "ksched: failed to add char dev\n");
		return ret;
	}

	printk(KERN_INFO "ksched: API V1 ready");
	return 0;
}

static void __exit ksched_exit(void)
{
	dev_t devno = MKDEV(KSCHED_MAJOR, KSCHED_MINOR);

	cdev_del(&ksched_cdev);
	unregister_chrdev_region(devno, 1);
}

module_init(ksched_init);
module_exit(ksched_exit);
