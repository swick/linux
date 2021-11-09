// SPDX-License-Identifier: GPL-2.0-only

#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>
#include <linux/ptrace.h>
#include <linux/pidfd.h>

#include <uapi/linux/pidfd.h>

struct pid *pidfd_pid(const struct file *file)
{
	if (file->f_op == &pidfd_fops)
		return file->private_data;

	return ERR_PTR(-EBADF);
}

static int pidfd_release(struct inode *inode, struct file *file)
{
	struct pid *pid = file->private_data;

	file->private_data = NULL;
	put_pid(pid);
	return 0;
}

#ifdef CONFIG_PROC_FS
/**
 * pidfd_show_fdinfo - print information about a pidfd
 * @m: proc fdinfo file
 * @f: file referencing a pidfd
 *
 * Pid:
 * This function will print the pid that a given pidfd refers to in the
 * pid namespace of the procfs instance.
 * If the pid namespace of the process is not a descendant of the pid
 * namespace of the procfs instance 0 will be shown as its pid. This is
 * similar to calling getppid() on a process whose parent is outside of
 * its pid namespace.
 *
 * NSpid:
 * If pid namespaces are supported then this function will also print
 * the pid of a given pidfd refers to for all descendant pid namespaces
 * starting from the current pid namespace of the instance, i.e. the
 * Pid field and the first entry in the NSpid field will be identical.
 * If the pid namespace of the process is not a descendant of the pid
 * namespace of the procfs instance 0 will be shown as its first NSpid
 * entry and no others will be shown.
 * Note that this differs from the Pid and NSpid fields in
 * /proc/<pid>/status where Pid and NSpid are always shown relative to
 * the  pid namespace of the procfs instance. The difference becomes
 * obvious when sending around a pidfd between pid namespaces from a
 * different branch of the tree, i.e. where no ancestral relation is
 * present between the pid namespaces:
 * - create two new pid namespaces ns1 and ns2 in the initial pid
 *   namespace (also take care to create new mount namespaces in the
 *   new pid namespace and mount procfs)
 * - create a process with a pidfd in ns1
 * - send pidfd from ns1 to ns2
 * - read /proc/self/fdinfo/<pidfd> and observe that both Pid and NSpid
 *   have exactly one entry, which is 0
 */
static void pidfd_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct pid *pid = f->private_data;
	struct pid_namespace *ns;
	pid_t nr = -1;

	if (likely(pid_has_task(pid, PIDTYPE_PID))) {
		ns = proc_pid_ns(file_inode(m->file)->i_sb);
		nr = pid_nr_ns(pid, ns);
	}

	seq_put_decimal_ll(m, "Pid:\t", nr);

#ifdef CONFIG_PID_NS
	seq_put_decimal_ll(m, "\nNSpid:\t", nr);
	if (nr > 0) {
		int i;

		/* If nr is non-zero it means that 'pid' is valid and that
		 * ns, i.e. the pid namespace associated with the procfs
		 * instance, is in the pid namespace hierarchy of pid.
		 * Start at one below the already printed level.
		 */
		for (i = ns->level + 1; i <= pid->level; i++)
			seq_put_decimal_ll(m, "\t", pid->numbers[i].nr);
	}
#endif
	seq_putc(m, '\n');
}
#endif

/*
 * Poll support for process exit notification.
 */
static __poll_t pidfd_poll(struct file *file, struct poll_table_struct *pts)
{
	struct pid *pid = file->private_data;
	__poll_t poll_flags = 0;

	poll_wait(file, &pid->wait_pidfd, pts);

	/*
	 * Inform pollers only when the whole thread group exits.
	 * If the thread group leader exits before all other threads in the
	 * group, then poll(2) should block, similar to the wait(2) family.
	 */
	if (thread_group_exited(pid))
		poll_flags = EPOLLIN | EPOLLRDNORM;

	return poll_flags;
}

const struct file_operations pidfd_fops = {
	.release = pidfd_release,
	.poll = pidfd_poll,
#ifdef CONFIG_PROC_FS
	.show_fdinfo = pidfd_show_fdinfo,
#endif
};

struct pid *pidfd_get_pid(unsigned int fd, unsigned int *flags)
{
	struct fd f;
	struct pid *pid;

	f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);

	pid = pidfd_pid(f.file);
	if (!IS_ERR(pid)) {
		get_pid(pid);
		*flags = f.file->f_flags;
	}

	fdput(f);
	return pid;
}

/**
 * pidfd_create() - Create a new pid file descriptor.
 *
 * @pid:   struct pid that the pidfd will reference
 * @flags: flags to pass
 *
 * This creates a new pid file descriptor with the O_CLOEXEC flag set.
 *
 * Note, that this function can only be called after the fd table has
 * been unshared to avoid leaking the pidfd to the new process.
 *
 * This symbol should not be explicitly exported to loadable modules.
 *
 * Return: On success, a cloexec pidfd is returned.
 *         On error, a negative errno number will be returned.
 */
int pidfd_create(struct pid *pid, unsigned int flags)
{
	int fd;

	if (!pid || !pid_has_task(pid, PIDTYPE_TGID))
		return -EINVAL;

	if (flags & ~(O_NONBLOCK | O_RDWR | O_CLOEXEC))
		return -EINVAL;

	fd = anon_inode_getfd("[pidfd]", &pidfd_fops, get_pid(pid),
			      flags | O_RDWR | O_CLOEXEC);
	if (fd < 0)
		put_pid(pid);

	return fd;
}

/**
 * pidfd_open() - Open new pid file descriptor.
 *
 * @pid:   pid for which to retrieve a pidfd
 * @flags: flags to pass
 *
 * This creates a new pid file descriptor with the O_CLOEXEC flag set for
 * the process identified by @pid. Currently, the process identified by
 * @pid must be a thread-group leader. This restriction currently exists
 * for all aspects of pidfds including pidfd creation (CLONE_PIDFD cannot
 * be used with CLONE_THREAD) and pidfd polling (only supports thread group
 * leaders).
 *
 * Return: On success, a cloexec pidfd is returned.
 *         On error, a negative errno number will be returned.
 */
SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
{
	int fd;
	struct pid *p;

	if (flags & ~PIDFD_NONBLOCK)
		return -EINVAL;

	if (pid <= 0)
		return -EINVAL;

	p = find_get_pid(pid);
	if (!p)
		return -ESRCH;

	fd = pidfd_create(p, flags);

	put_pid(p);
	return fd;
}

static struct file *__pidfd_fget(struct task_struct *task, int fd)
{
	struct file *file;
	int ret;

	ret = down_read_killable(&task->signal->exec_update_lock);
	if (ret)
		return ERR_PTR(ret);

	if (ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS))
		file = fget_task(task, fd);
	else
		file = ERR_PTR(-EPERM);

	up_read(&task->signal->exec_update_lock);

	return file ?: ERR_PTR(-EBADF);
}

static int pidfd_getfd(struct pid *pid, int fd)
{
	struct task_struct *task;
	struct file *file;
	int ret;

	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task)
		return -ESRCH;

	file = __pidfd_fget(task, fd);
	put_task_struct(task);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ret = receive_fd(file, O_CLOEXEC);
	fput(file);

	return ret;
}

/**
 * sys_pidfd_getfd() - Get a file descriptor from another process
 *
 * @pidfd:	the pidfd file descriptor of the process
 * @fd:		the file descriptor number to get
 * @flags:	flags on how to get the fd (reserved)
 *
 * This syscall gets a copy of a file descriptor from another process
 * based on the pidfd, and file descriptor number. It requires that
 * the calling process has the ability to ptrace the process represented
 * by the pidfd. The process which is having its file descriptor copied
 * is otherwise unaffected.
 *
 * Return: On success, a cloexec file descriptor is returned.
 *         On error, a negative errno number will be returned.
 */
SYSCALL_DEFINE3(pidfd_getfd, int, pidfd, int, fd,
		unsigned int, flags)
{
	struct pid *pid;
	struct fd f;
	int ret;

	/* flags is currently unused - make sure it's unset */
	if (flags)
		return -EINVAL;

	f = fdget(pidfd);
	if (!f.file)
		return -EBADF;

	pid = pidfd_pid(f.file);
	if (IS_ERR(pid))
		ret = PTR_ERR(pid);
	else
		ret = pidfd_getfd(pid, fd);

	fdput(f);
	return ret;
}
