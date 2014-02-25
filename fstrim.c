void mydirnm(char* nm)
{
	char* last = nm+strlen(nm)-1;
	while (last > nm && *last != '/')
		--last;
	if (last == nm) {
		*nm++ = '.'; *nm = 0;
	} else 
		*++nm = 0;
}

void remove_and_trim(const char* onm)
{
	int err = unlink(onm);
	if (err)
		fplog(stderr, WARN, "remove(%s) failed: %s\n",
			onm, strerror(errno));
#ifdef FITRIM
	char* dirnm = strdup(onm);
	mydirnm(dirnm);
	struct fstrim_range trim;
	int fd = open(dirnm, O_RDONLY);
	if (fd < 0) {
		fplog(stderr, WARN, "Can't open dir %s for fstrim: %s\n",
			dirnm, strerror(errno));
		free(dirnm);
		return;
	}
	trim.start = 0;
	trim.len = (__u64)(-1);
	trim.minlen = 16384;
	fprintf(stderr, "dd_rescue: FITRIM %s ...\r", dirnm); 
	fflush(stderr);
	int trimerr = ioctl(fd, FITRIM, &trim);
	if (trimerr) 
		fplog(stderr, WARN, "fstrim %s failed: %s%s\n", 
			dirnm, strerror(errno), (errno == EPERM? " (have root?)": ""));
	else
		fplog(stderr, INFO, "Trimmed %skiB \n", 
				fmt_int(0, 0, 1024, trim.len, BOLD, NORM, 1));
	close(fd);
	free(dirnm);
#endif
}


