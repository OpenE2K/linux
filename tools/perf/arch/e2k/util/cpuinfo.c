#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/string.h>

#include "../include/cpuinfo.h"

static int read_cpuinfo(const char *field, char *value, int len)
{
	FILE *f;
	int ret = -1;
	int field_len = strlen(field);
	char line[4096];

	f = fopen("/proc/cpuinfo", "r");
	if (!f) {
		return -1;
	}

	do {
		if (!fgets(line, sizeof(line), f)) {
			break;
		}
		if (!strncmp(line, field, field_len)) {
			strlcpy(value, line, len);
			ret = 0;
			break;
		}
	} while (*line);

	fclose(f);

	return ret;
}

/*
 * Checks a feature in /proc/cpuinfo.  If value!=NULL, get number
 * after "=" (for example, for epic=100000000 will extract 100000000).
 *
 * Returns -1 on error, 0 if feature is not available or missing
 * value, 1 otherwise.
 */
int e2k_cpuinfo_feature(const char *feature, uint64_t *value)
{
	char line[4096];
	char *result;
	size_t feature_len = strlen(feature);

	if (!feature_len || read_cpuinfo("features", line, sizeof(line)))
		return -1;

	result = strchr(line, ':');
	if (!result)
		return -1;
	result++;

	for (;;) {
		char next;

		result = strstr(result, feature);
		if (!result)
			return 0;

		/* Check word boundary */
		if (result > line) {
			char prev = result[-1];
			if (prev != ' ') {
				result += feature_len;
				continue;
			}
		}
		next = result[feature_len];
		if (!value && next != '\n' && next != ' ' && next != '\0' ||
		    value && next != '=') {
			result += feature_len;
			continue;
		}

		break;
	}

	if (value) {
		char *space = strchr(result, ' ');
		char *assign = strchr(result, '=');
		if (!assign || space && space < assign)
			return 0;
		*value = strtoull(assign + 1, NULL, 10);
	}

	return 1;
}