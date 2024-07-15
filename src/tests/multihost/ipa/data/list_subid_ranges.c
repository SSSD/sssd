#include <stdio.h>
#include <string.h>
#include "shadow/subid.h"
#include "stdlib.h"
#if !defined(SUBID_ABI_MAJOR) || (SUBID_ABI_MAJOR < 4)
#define subid_get_gid_ranges get_subgid_ranges
#define subid_get_uid_ranges get_subuid_ranges
#endif

const char *Prog;
FILE *shadow_logfd = NULL;

void usage(void)
{
	fprintf(stderr, "Usage: %s [-g] user\n", Prog);
	fprintf(stderr, "    list subuid ranges for user\n");
	fprintf(stderr, "    pass -g to list subgid ranges\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int i, count=0;
	struct subid_range *ranges;
	const char *owner;

	Prog = argv[0];
	shadow_logfd = stderr;
	if (argc < 2)
		usage();
	owner = argv[1];
	if (argc == 3 && strcmp(argv[1], "-g") == 0) {
		owner = argv[2];
		count = subid_get_gid_ranges(owner, &ranges);
	} else if (argc == 2 && strcmp(argv[1], "-h") == 0) {
		usage();
	} else {
		count = subid_get_uid_ranges(owner, &ranges);
	}
	if (!ranges) {
		fprintf(stderr, "Error fetching ranges\n");
		exit(1);
	}
	for (i = 0; i < count; i++) {
		printf("%d: %s %lu %lu\n", i, owner,
			ranges[i].start, ranges[i].count);
	}
	return 0;
}
