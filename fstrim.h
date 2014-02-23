#ifndef _FSTRIM_H
#define _FSTRIM_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#include <sys/ioctl.h>

#if defined(__linux__) && !defined(FITRIM)
struct fstrim_range {
	__u64 start;
	__u64 len;
	__u64 minlen;
};
# define FITRIM		_IOWR('X', 121, struct fstrim_range)	/* Trim */
#endif

#endif	/* HAVE_LINUX_FS_H */
#endif /* _FSTRIM_H */
