#include "cache.h"

int compare_ce(const struct cache_entry *ce1, const struct cache_entry *ce2)
{
	/*	struct hashmap_entry ent; */
	/*	struct stat_data ce_stat_data; */

	if (ce1->ce_mode != ce2->ce_mode) {
		printf("ce_mode: %d:%d\n", ce1->ce_mode, ce2->ce_mode);
		return 1;
	}

	if (ce1->ce_flags != ce2->ce_flags) {
		printf("ce_flags: %d:%d\n", ce1->ce_flags, ce2->ce_flags);
		return 1;
	}

	if (ce1->ce_namelen != ce2->ce_namelen) {
		printf("namelen: %d:%d\n", ce1->ce_namelen, ce2->ce_namelen);
		return 1;
	}

	if (ce1->index != ce2->index) {
		printf("index: %d:%d\n", ce1->index, ce2->index);
		return 1;
	}

	if (oidcmp(&ce1->oid, &ce2->oid)) {
		printf("oid: %s:%s\n", oid_to_hex(&ce1->oid), oid_to_hex(&ce2->oid));
		return 1;
	}

	if (strcmp(ce1->name, ce2->name)) {
		printf("name: %s:%s\n", ce1->name, ce2->name);
		return 1;
	}


	return 0;
}

extern int ignore_fast_index_config;

int cmd_main(int ac, const char **av)
{
#ifndef NO_PTHREADS
	static struct index_state index;
	static struct index_state ieot;
	int i, err = 0;

	setup_git_directory();
	ignore_fast_index_config = 1;
	core_fast_index = 0;
	read_index(&index);
	core_fast_index = 1;
	read_index(&ieot);

	for (i = 0; i < index.cache_nr; i++) {
		if (compare_ce(index.cache[i], ieot.cache[i])) {
			struct cache_entry *ce;

			ce = index.cache[i];
			printf("%06o %s %d\t%s\n", ce->ce_mode,
				oid_to_hex(&ce->oid), ce_stage(ce), ce->name);
			ce = ieot.cache[i];
			printf("%06o %s %d\t%s\n", ce->ce_mode,
				oid_to_hex(&ce->oid), ce_stage(ce), ce->name);

			printf("cache entry %d does not match", i);
			err = 1;
			break;
		}
	}

	discard_index(&ieot);
	discard_index(&index);
	if (!err)
		printf("Cache entires are the same\n");
	return err;
#else
	die("ieot only supported with PTHREADS");
	return -1;
#endif
}
