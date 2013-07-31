#define _GNU_SOURCE
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "find_nonzero.h"

#define BUFSZ (64*1024)
unsigned char buf[BUFSZ];

void usage()
{
	fprintf(stderr, "Usage: file_zblock FILE1 [FILE2 [FILE3 [...]]]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int zf = 0;
	int chunksz = 4096;
	int i = 1, off;
	if (argc < 2)
		usage();
	if (!memcmp(argv[1], "-c", 2)) {
		if (strlen(argv[1]) > 2) {
			chunksz = atoi(argv[1]+2);
			++i;
		} else {
			chunksz = atoi(argv[2]);
			i += 2;
		}
	}
	for (; i < argc; ++i) {
		int fd = open(argv[i], O_RDONLY);
		if (fd<0) {
			fprintf(stderr, "ERROR opening file %s: %s\n", argv[i], strerror(errno));
			continue;
		}
		int rd, found = 0;
		while ((rd = read(fd, buf, BUFSZ)) > 0 && !found) {
			for (off = 0; off < rd; off += chunksz) {
				int tocheck = rd-off > chunksz? chunksz: rd-off;
				if (find_nonzero(buf+off, tocheck) == tocheck) {
					++found; ++zf;
					printf("%s,%i\n", argv[i], off);
					break;
				}
			}
		}
		close(fd);
	}
	return zf;
}
