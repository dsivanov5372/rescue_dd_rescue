/* fiemap.c */
/* Implements the routines to locate blocks of a file
 * in the block device the holds the filesystem.
 * It uses Linux' fiemap icotl and does some additional
 * sanity checks.
 */

#define _LARGEFILE_SOURCE 1
#define _FILE_OFFSET_BITS 64
#include "fiemap.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

int alloc_and_get_mapping(int fd, uint64_t start, uint64_t len, struct fiemap_extent **ext)
{
	int err;
	struct fiemap fmap;
	//struct fiemap_extent *fmap_exts;
	fmap.fm_start = start;
	fmap.fm_length = len;
	fmap.fm_flags = FIEMAP_FLAG_SYNC;
	fmap.fm_extent_count = 0;
	err = ioctl(fd, FS_IOC_FIEMAP, &fmap);
	if (err != 0)
		return -errno;
	struct fiemap *fm = (struct fiemap*) malloc(sizeof(struct fiemap) 
			+ sizeof(struct fiemap_extent)*fmap.fm_mapped_extents);
	if (!fm)
		return -errno;
	fm->fm_start = start;
	fm->fm_length = len;
	fm->fm_flags = 0;
	fm->fm_extent_count = fmap.fm_mapped_extents;
	err = ioctl(fd, FS_IOC_FIEMAP, fm);
	if (err != 0) {
		free(fm);
		ext = NULL;
		return -errno;
	}
	*ext = fm->fm_extents;
	return fm->fm_mapped_extents;
}

void free_mapping(struct fiemap_extent *ext)
{
	if (ext)
		free(((char*)ext) - sizeof(struct fiemap));
}

#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
static char _devnm_str[64];
char* devname(dev_t dev)
{
	/* FIXME: Need to accommodate > 16bits ... */
	int maj = (dev & 0xff00) >> 8;
	int min = (dev & 0xff);
	char partln[128];
	FILE *f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;
	int found = 0;
	char pnm[32];
	while (fgets(partln, 128, f) != 0) {
		int pmaj, pmin, psz;
		if (!*partln || *partln == '\n' || isalpha(*partln))
			continue;
		sscanf(partln, "%i %i %i %s",
			&pmaj, &pmin, &psz, pnm);
		if (maj == pmaj && min == pmin) {
			++found;
			break;
		}
	}
	fclose(f);
	if (!found)
		return NULL;
	struct stat st;
	sprintf(_devnm_str, "/dev/%s", pnm);
	if (!stat(_devnm_str, &st))
		if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
			return _devnm_str;
	sprintf(_devnm_str, "/dev/block/%s", pnm);
	if (!stat(_devnm_str, &st))
		if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
			return _devnm_str;
	return NULL;
}

static char _fiemap_str[128];
char* fiemap_str(uint32_t flags)
{
	_fiemap_str[0] = 0;
	if (flags & FIEMAP_EXTENT_UNKNOWN)
		strcat(_fiemap_str, "UNKNOWN ");
	if (flags & FIEMAP_EXTENT_DELALLOC)
		strcat(_fiemap_str, "(DELALLOC) ");
	if (flags & FIEMAP_EXTENT_ENCODED)
		strcat(_fiemap_str, "ENCODED ");
	if (flags & FIEMAP_EXTENT_DATA_ENCRYPTED)
		strcat(_fiemap_str, "(DATA_ENCRYPTED) ");
	if (flags & FIEMAP_EXTENT_NOT_ALIGNED)
		strcat(_fiemap_str, "NOT_ALIGNED ");
	if (flags & FIEMAP_EXTENT_DATA_INLINE)
		strcat(_fiemap_str, "(DATA_INLINE) ");
	if (flags & FIEMAP_EXTENT_DATA_TAIL)
		strcat(_fiemap_str, "(DATA_TAIL) ");
	if (flags & FIEMAP_EXTENT_UNWRITTEN)
		strcat(_fiemap_str, "UNWRITTEN ");
	if (flags & FIEMAP_EXTENT_MERGED)
		strcat(_fiemap_str, "MERGED ");
	if (flags & FIEMAP_EXTENT_LAST)
		strcat(_fiemap_str, "LAST ");
	return _fiemap_str;
}

#ifdef TEST_FIEMAP
#include <fcntl.h>
#include <unistd.h>

#if __WORDSIZE == 64
#define LL "l"
#else
#define LL "L"
#endif

void usage()
{
	fprintf(stderr, "Usage: fiemap FILENAME [FILENAME [...]]\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int fno, errs = 0;
	if (argc < 2)
		usage();
	for (fno = 1; fno < argc; ++fno) {
		struct fiemap_extent *ext = NULL;
		struct stat st;
		int i, err, fd = open(argv[fno], O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open %s: %s\n", argv[fno], strerror(errno));
			++errs;
			continue;
		}
		err = fstat(fd, &st);
		if (err) {
			fprintf(stderr, "Can't stat %s: %s\n", argv[fno], strerror(errno));
			close(fd);
			++errs;
			continue;
		}
		err = alloc_and_get_mapping(fd, 0, st.st_size, &ext);
		if (err <= 0) {
			fprintf(stderr, "Can't get extents for %s: %s\n", argv[fno], strerror(-err));
			close(fd);
			++errs;
			continue;
		}
		printf("Extents for %s (ino %" LL "i) on dev %s (0x%08" LL "x bytes): %i\n",
			argv[fno], st.st_ino, devname(st.st_dev), st.st_size, err);
		for (i = 0; i < err; ++i)
			printf(" %08" LL "x @ %010" LL "x: %012" LL "x %s\n", 
				(uint64_t)ext[i].fe_length,
				(uint64_t)ext[i].fe_logical, 
				(uint64_t)ext[i].fe_physical,
				fiemap_str(ext[i].fe_flags));
		if ((ext[err-1].fe_flags & FIEMAP_EXTENT_LAST) == 0)
			printf(" (INCOMPLETE)\n");
		free_mapping(ext);
		close(fd);
	}
	return errs;
}
#endif

