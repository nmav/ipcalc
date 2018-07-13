#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

int __attribute__((__format__(printf, 2, 3))) safe_asprintf(char **strp, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vasprintf(&(*strp), fmt, args);
	va_end(args);
	if (ret < 0) {
		fprintf(stderr, "Memory allocation failure\n");
		exit(1);
	}
	return ret;
}
