/* 层参数解析：qrng-cli 与 qrng-server 共用（改动一处两边生效）。 */
#include "opts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int on_off_value(const char *opt, const char *v, int *out) {
	if (strcmp(v, "on") == 0) {
		*out = 1;
		return 1;
	}
	if (strcmp(v, "off") == 0) {
		*out = 0;
		return 1;
	}
	fprintf(stderr, "%s expects on|off, got '%s'\n", opt, v);
	return 0;
}

int qrng_opts_try_parse(int argc, char **argv, int *argi,
                        qrng_core_conf_t *cfg) {
	if (*argi + 1 >= argc) {
		return 0;
	}
	const char *arg = argv[*argi];
	const char *val = argv[*argi + 1];
	int ok = 0;
	int flag = 0;
	if (strcmp(arg, "--health") == 0) {
		ok = on_off_value(arg, val, &flag);
		if (ok) {
			cfg->health.enabled = flag;
		}
	} else if (strcmp(arg, "--condition") == 0) {
		ok = on_off_value(arg, val, &flag);
		if (ok) {
			cfg->condition.enabled = flag;
		}
	} else if (strcmp(arg, "--drbg") == 0) {
		ok = on_off_value(arg, val, &flag);
		if (ok) {
			cfg->drbg.enabled = flag;
		}
	} else if (strcmp(arg, "--reseed-interval") == 0) {
		cfg->drbg.reseed_interval = strtoull(val, NULL, 0);
		ok = 1;
	} else if (strcmp(arg, "--reseed-bytes") == 0) {
		cfg->drbg.reseed_bytes = strtoull(val, NULL, 0);
		ok = 1;
	} else if (strcmp(arg, "--reseed-seconds") == 0) {
		cfg->drbg.reseed_seconds = strtoull(val, NULL, 0);
		ok = 1;
	} else if (strcmp(arg, "--min-entropy") == 0) {
		cfg->health.min_entropy_bits = strtod(val, NULL);
		cfg->condition.min_entropy_bits = cfg->health.min_entropy_bits;
		ok = 1;
	} else if (strcmp(arg, "--alpha-log2") == 0) {
		cfg->health.alpha_log2 = (unsigned)strtoul(val, NULL, 0);
		ok = 1;
	} else if (strcmp(arg, "--startup") == 0) {
		cfg->health.startup_samples = (unsigned)strtoul(val, NULL, 0);
		ok = 1;
	} else {
		return 0;
	}
	if (!ok) {
		return -1;
	}
	*argi += 2;
	return 1;
}