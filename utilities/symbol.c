#include <limits.h>
#include <inttypes.h>
#include "symbol.h"
#include "kallsyms.h"

int modules__parse(const char *procdir, const char *sysdir, void *arg,
		   int (*process_module)(void *arg, const char *name, u64 start,
					 u64 size, u64 lastaddr))
{

	char *line = NULL;
	size_t n;
	FILE *file;
	int err = 0;
	char modules_filename[PATH_MAX];

	snprintf(modules_filename, PATH_MAX, "%s/modules", procdir);

	file = fopen(modules_filename, "r");
	if (file == NULL)
		return -1;

	while (1) {
		char name[PATH_MAX], symtab_file[PATH_MAX];
		FILE* symtabf = NULL;
		u64 start, size, lastaddr = 0;
		char *sep, *endptr;
		ssize_t line_len;

		line_len = getline(&line, &n, file);
		if (line_len < 0) {
			if (feof(file))
				break;
			err = -1;
			goto out;
		}

		if (!line) {
			err = -1;
			goto out;
		}

		line[--line_len] = '\0'; /* \n */

		sep = strrchr(line, 'x');
		if (sep == NULL)
			continue;

		hex2u64(sep + 1, &start);

		sep = strchr(line, ' ');
		if (sep == NULL)
			continue;

		*sep = '\0';

		snprintf(name, sizeof(name), "[%s]", line);

		size = strtoul(sep + 1, &endptr, 0);
		if (*endptr != ' ' && *endptr != '\t')
			continue;

		if (sysdir != NULL) {
			snprintf(symtab_file, sizeof(symtab_file),
				 "%s/module/%s/sections/.symtab", sysdir, line);
			symtabf = fopen(symtab_file, "r");
		}
		if (symtabf != NULL) {
			fscanf(symtabf, "0x%" PRIx64, &lastaddr);
			fclose(symtabf);
		}

		err = process_module(arg, name, start, size, lastaddr);
		if (err)
			break;
	}
out:
	free(line);
	fclose(file);
	return err;
}
