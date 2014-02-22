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


static ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}

static ssize_t pwrite64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}

#endif
