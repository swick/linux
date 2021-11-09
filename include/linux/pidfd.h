/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PIDFD_H
#define _LINUX_PIDFD_H

#include <linux/pid.h>
#include <linux/fs.h>

extern const struct file_operations pidfd_fops;

extern struct pid *pidfd_pid(const struct file *file);
struct pid *pidfd_get_pid(unsigned int fd, unsigned int *flags);
int pidfd_create(struct pid *pid, unsigned int flags);

#endif /* _LINUX_PIDFD_H */
