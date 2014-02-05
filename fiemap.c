/* fiemap.c */
/* Implements the routines to locate blocks of a file
 * in the block device the holds the filesystem.
 * It uses Linux' fiemap icotl and does some additional
 * sanity checks.
 */

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
#define _LARGEFILE_SOURCE 1
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

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
		printf("Extents for %s (ino %li) on dev 0x%04x (0x%08lx bytes): %i\n",
			argv[fno], st.st_ino, st.st_dev, st.st_size, err);
		for (i = 0; i < err; ++i)
			printf(" %08lx @ %010lx: %012lx %s\n", ext[i].fe_length,
				ext[i].fe_logical, ext[i].fe_physical,
				fiemap_str(ext[i].fe_flags));
		if ((ext[err-1].fe_flags & FIEMAP_EXTENT_LAST) == 0)
			printf(" (INCOMPLETE)\n");
		free_mapping(ext);
		close(fd);
	}
	return errs;
}
#endif

