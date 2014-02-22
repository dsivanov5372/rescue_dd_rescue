/* fiemap.h */
/* Header file, declaring the data structures and functions
 * to obtain the blocks from the block device that contain
 * the file contents
 */
/* (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPL v2 or v3
 */

#ifndef _FIEMAP_H
#define _FIEMAP_H

#include <linux/fs.h>
#ifdef HAVE_LINUX_FIEMAP
# include <linux/fiemap.h>
#else
# include "linux_fiemap.h"
#endif

#ifndef FS_IOC_FIEMAP
# define FS_IOC_FIEMAP			_IOWR('f', 11, struct fiemap)
#endif

#endif

