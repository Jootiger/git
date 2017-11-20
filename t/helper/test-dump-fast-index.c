#include "cache.h"

int cmd_main(int ac, const char **av)
{
#ifndef NO_PTHREADS
	const char *path;
	int fd, i;
	struct stat st;
	void *mmap;
	size_t mmap_size;
	struct cache_header *hdr;
	struct index_entry_offset_table *ieot;
	struct strbuf previous_name_buf = STRBUF_INIT, *previous_name;
	int err = 0;

	setup_git_directory();
	path = get_index_file();
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		die("%s: index file open failed", path);
	}

	if (fstat(fd, &st))
		die("cannot stat the open index");

	mmap_size = xsize_t(st.st_size);
	if (mmap_size < sizeof(struct cache_header) + GIT_SHA1_RAWSZ)
		die("index file smaller than expected");

	mmap = xmmap(NULL, mmap_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mmap == MAP_FAILED)
		die("unable to map index file");
	close(fd);

	hdr = mmap;
	if (ntohl(hdr->hdr_version) == 4)
		previous_name = &previous_name_buf;
	else
		previous_name = NULL;

	ieot = read_ieot_extension(mmap, mmap_size);
	if (ieot) {
		printf("IEOT with %d entries\n", ieot->nr);
		printf("  Offset    Count Name\n");
		printf("-------- -------- ------------------------\n");
		for (i = 0; i < ieot->nr; i++) {
			struct ondisk_cache_entry *disk_ce;
			struct cache_entry *ce;
			unsigned long consumed;

			disk_ce = (struct ondisk_cache_entry *)((char *)mmap + ieot->entries[i].offset);
			ce = create_from_disk(disk_ce, &consumed, previous_name, 0);
			printf("%8d %8d %.*s\n", ieot->entries[i].offset, ieot->entries[i].nr, ce->ce_namelen, ce->name);
			free(ce);
		}
	} else {
		printf("missing or invalid extension");
		err = 1;
	}

	free(ieot);
	munmap(mmap, mmap_size);
	return err;
#else
	die("ieot only supported with PTHREADS");
	return -1;
#endif
}
