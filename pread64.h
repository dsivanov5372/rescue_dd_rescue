/** pread64.h 
 *
 * Implements pread64() for platforms where the libc misses it
 * - implementing a syscall wrapper for linux
 * - using lseek64 and read
 * - or using plain pread in the worst case ...
 * Likewise for pwrite64()
 */

#ifndef _PREAD64_H
#define _PREAD64_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_PREAD64

#ifdef __linux__
# include <sys/syscall.h>
# include <sys/types.h>
# ifdef HAVE_ENDIAN_H
#  include <endian.h>
# endif
# define __KERNEL__
# include <asm/unistd.h>
# ifdef __NR_pread64
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
#if __WORDSIZE == 64
	return syscall(__NR_pread64, fd, buf, sz, off);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
# warning 32bit wrapper little endian pread64
	return syscall(__NR_pread64, fd, buf, sz, (unsigned int)off, (int)(off >> 32));
#else
# warning 32bit wrapper big endian pread64
	return syscall(__NR_pread64, fd, buf, sz, (int)(off >> 32), (unsigned int)off);
#endif
}

static inline ssize_t pwrite64(int fd, void *buf, size_t sz, loff_t off)
{
#if __WORDSIZE == 64
	return syscall(__NR_pwrite64, fd, buf, sz, off);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	return syscall(__NR_pwrite64, fd, buf, sz, (unsigned int)off, (int)(off >> 32));
#else
	return syscall(__NR_pwrite64, fd, buf, sz, (int)(off >> 32), (unsigned int)off);
#endif
}
#  define HAVE_PREAD64
# endif
#endif

#ifndef HAVE_PREAD64
# ifdef HAVE_LSEEK64
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}

static inline ssize_t pwrite64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}
# elif defined(HAVE_PREAD)
#  warning Using plain pread will likely limit file size to 2GB
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	return pread(fd, buf, sz, off);
}
static inline ssize_t pwrite(int fd, void *buf, size_t sz, loff_t off)
{
	return pwrite(fd, buf, sz, off);
}
# else
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}

static inline ssize_t pwrite64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}
# endif
#endif /* HAVE_PREAD64 -- after syscall wrapper */

#else
# warning No need to include pread64.h if we have pread64() in libc
#endif /* HAVE_PREAD64 */

#endif /* _PREAD64_H */
