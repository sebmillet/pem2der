/*
 * =====================================================================================
 *
 *       Filename:  pem2der.c
 *
 *    Description:  Crypto: convert PEM to DER format
 *
 *        Version:  1.0
 *        Created:  27/12/2015 10:38:44
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

/*#define DEBUG*/

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#include "ppem.h"

#define PACKAGE_NAME "pem2der"

#define UNUSED(x) (void)(x)

#ifdef DEBUG
#define DBG(...) \
{\
	fprintf(stderr, "%s[%d]\t", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
}
#else
#define DBG(...)
#endif

char *file_in = NULL;
char *file_out = NULL;

char *opt_password = NULL;

int opt_walker = 0;

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "./pem2der [OPTIONS]... FILE\n");
	fprintf(stderr, "Decode and decrypt PEM files.\n");
	fprintf(stderr, "  -h  --help          print this help and exit\n");
	fprintf(stderr, "  -v  --version       print version information and exit\n");
	fprintf(stderr, "  -o  --out FILE      output to FILE instead of stdout\n");
	exit(-1);
}

void version()
{
	fprintf(stderr, "pem2der 0.1\n");
	fprintf(stderr, "Copyright 2015 Sébastien Millet\n");
	exit(-2);
}

char *s_strncpy(char *dest, const char *src, size_t n)
{
		strncpy(dest, src, n);
		dest[n - 1] = '\0';
		return dest;
}
	/* The define below triggers an error if usual strncpy is used */
#define strncpy(a, b, c) ErrorDontUse_strncpy_Use_s_strncpy_Instead

	/*
	 * Returns a copied, allocated string. Uses s_strncpy for the string
	 * copy (see comment above).
	 * dst can be null, in which case the new string is to be retrieved
	 * by the function return value.
	 */
char *s_alloc_and_copy(char **dst, const char *src)
{
	unsigned int s = strlen(src) + 1;
	char *target = (char *)malloc(s);
	s_strncpy(target, src, s);
	if (dst)
		*dst = target;
	return target;
}

ssize_t file_size(const char* filename)
{
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}

static void opt_check(unsigned int n, const char *opt)
{
	static int defined_options[3] = {0, 0, 0};

	assert(n < sizeof(defined_options) / sizeof(*defined_options));

	if (defined_options[n]) {
		fprintf(stderr, "Option %s already set\n", opt);
		exit(-2);
	} else
		defined_options[n] = 1;
}

static void parse_options(int argc, char **argv)
{
#define OPT_WITH_VALUE_CHECK \
if (shortopt_nb >= 1 && shortopt_i < shortopt_nb - 1) { \
	missing_option_value = argv_a_short + 1; \
	a = -1; \
	break; \
} \
if (++a >= argc) { \
	missing_option_value = argv[a - 1] + 1; \
	a = -1; \
	break; \
}

	char *missing_option_value = NULL;

	int a = 1;
	char *argv_a_short;
	char shortopt[3];
	int shortopt_nb = 0;
	int shortopt_i = -1;
	while (a < argc) {
		if (shortopt_nb == 0) {
			if (strlen(argv[a]) >= 2 && argv[a][0] == '-' && argv[a][1] != '-') {
				shortopt_nb = strlen(argv[a]) - 1;
				shortopt_i = 0;
			}
		}
		if (shortopt_nb >= 1) {
			assert(shortopt_i <= shortopt_nb);
			shortopt[0] = '-';
			shortopt[1] = argv[a][shortopt_i + 1];
			shortopt[2] = '\0';
			argv_a_short = shortopt;
		} else {
			argv_a_short = argv[a];
		}

		if (!strcmp(argv[a], "--help") || !strcmp(argv_a_short, "-h")) {
			usage();
		} else if (!strcmp(argv[a], "--version") || !strcmp(argv_a_short, "-v")) {
			version();
			exit(0);
		} else if (!strcmp(argv[a], "--out") || !strcmp(argv_a_short, "-o")) {
			opt_check(0, argv[a]);
			OPT_WITH_VALUE_CHECK
			file_out = argv[a];
		} else if (!strcmp(argv[a], "--walker") || !strcmp(argv_a_short, "-w")) {
			opt_check(1, argv[a]);
			opt_walker = 1;
		} else if (!strcmp(argv[a], "--password")) {
			opt_check(2, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_password = argv[a];
		} else if (argv[a][0] == '-') {
			if (strcmp(argv[a], "--")) {
				fprintf(stderr, "%s: invalid option -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			} else {
				++a;
				break;
			}
		} else {
			if (!file_in) {
				file_in = argv[a];
			} else {
				fprintf(stderr, "%s: invalid argument -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			}
		}
		if (shortopt_nb >= 1) {
			if (++shortopt_i >= shortopt_nb)
				shortopt_nb = 0;
		}
		if (shortopt_nb == 0)
			++a;
	}
	if ((a >= 1 && a < argc - 1) || (a >= 1 && a == argc - 1 && file_in)) {
		fprintf(stderr, "%s: trailing options.\n", PACKAGE_NAME);
		a = -1;
	} else if (a >= 1 && a == argc - 1) {
		file_in = argv[a];
	} else if (missing_option_value) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option_value);
	}
	if (a < 0)
		usage();
	if (!file_in) {
		fprintf(stderr, "%s: you must specify the input file\n", PACKAGE_NAME);
		usage();
	}
}

char *cb_password_pre()
{
	char *password;

	char *readpwd;
	if (!opt_password) {
		fprintf(stderr, "Please type in the password:\n");
		readpwd = NULL;
		size_t s = 0;
		if (getline(&readpwd, &s, stdin) < 0) {
			if (readpwd)
				free(readpwd);
			return NULL;
		}
		password = readpwd;
	} else {
		password = s_alloc_and_copy(NULL, opt_password);
	}

	int i;
	for (i = 0; i < 2; ++i) {
		int n = strlen(password);
		if (n >= 1 && (password[n - 1] == '\n' || password[n - 1] == '\r'))
			password[n - 1] = '\0';
	}

	DBG("Password: '%s'", password)

	return password;
}

void cb_password_post(char *password)
{
	if (password)
		free(password);
}

void cb_loop_top(const pem_ctrl_t *ctrl)
{
	void print_hexa(FILE *o, const unsigned char *buf, int buf_len) {
		int i; for (i = 0; i < buf_len; ++i) fprintf(o, "%02X", (unsigned char)buf[i]);
	}

	if (!pem_has_data(ctrl)) {
		DBG("pem_walker(): [%s] (skipped: %s)", pem_header(ctrl), pem_errorstring(pem_status(ctrl)))
		fprintf(stderr, "[%s] (skipped: %s)\n", pem_header(ctrl), pem_errorstring(pem_status(ctrl)));
		return;
	}

	if (pem_has_encrypted_data(ctrl)) {
		DBG("pem_walker(): [%s] (encrypted: '%s')", pem_header(ctrl), pem_cipher(ctrl))
		fprintf(stderr, "[%s] (encrypted with %s", pem_header(ctrl), pem_cipher(ctrl));
		if (!pem_salt(ctrl))
			fprintf(stderr, ", no salt)\n");
		else {
			fprintf(stderr, ", salt: ");
			print_hexa(stderr, pem_salt(ctrl), pem_salt_len(ctrl));
			fprintf(stderr, ")\n");
		}
	} else {
		fprintf(stderr, "[%s]\n", pem_header(ctrl));
	}
}

void cb_loop_decrypt(int decrypt_ok, const char *errmsg)
{
	if (!decrypt_ok)
		fprintf(stderr, "%s\n", errmsg);
}

void cb_loop_bottom(const unsigned char *data_src, size_t data_src_len)
{
UNUSED(data_src);
UNUSED(data_src_len);
}

void use_my_own_pem_walker(const unsigned char *data_in, unsigned char **data_out, size_t *data_out_len)
{
	DBG("use_my_own_pem_walker() start")

	*data_out = NULL;
	*data_out_len = 0;

	pem_openssl_start();

	pem_ctrl_t *ctrl = pem_construct_pem_ctrl(data_in);
	pem_regcb_password(ctrl, cb_password_pre, cb_password_post);
	while (pem_next(ctrl)) {
		cb_loop_top(ctrl);
		if (!pem_has_data(ctrl))
			continue;

		unsigned char *data_src;
		size_t data_src_len;
		int data_src_is_readonly;
		if (!pem_has_encrypted_data(ctrl)) {
			data_src = (unsigned char *)pem_bin(ctrl);
			data_src_len = pem_bin_len(ctrl);
			data_src_is_readonly = 1;
		} else {
			data_src = NULL;
			data_src_len = 0;

			unsigned char *out;
			int out_len;
			const char *errmsg;
			if (pem_decrypt(ctrl, &out, &out_len, &errmsg) == 1) {
				data_src = out;
				data_src_len = out_len;
				data_src_is_readonly = 0;
				cb_loop_decrypt(1, NULL);
			} else {
				DBG("pem_walker(): decrypt error: %s", errmsg)
				cb_loop_decrypt(0, errmsg);
			}
		}
		cb_loop_bottom(data_src, data_src_len);
		if (data_src) {
			unsigned char *target;
			if (!*data_out) {
				*data_out = malloc(data_src_len);
				target = *data_out;
				*data_out_len = 0;
			} else {
				*data_out = realloc(*data_out, *data_out_len + data_src_len);
				target = *data_out + *data_out_len;
			}
			memcpy(target, data_src, data_src_len);
			*data_out_len += data_src_len;
			if (!data_src_is_readonly)
				free(data_src);
		}
	}
	pem_destruct_pem_ctrl(ctrl);
	pem_openssl_terminate();

	DBG("use_my_own_pem_walker() end")
}

void use_pem_walker_provided_by_ppem(const unsigned char *data_in, unsigned char **data_out, size_t *data_out_len)
{
	DBG("use_pem_walker_provided_by_ppem() start")

	pem_ctrl_t *ctrl = pem_construct_pem_ctrl(data_in);

	pem_regcb_password(ctrl, cb_password_pre, cb_password_post);
	pem_regcb_loop_top(ctrl, cb_loop_top);
	pem_regcb_loop_decrypt(ctrl, cb_loop_decrypt);
	pem_regcb_loop_bottom(ctrl, cb_loop_bottom);

	pem_walker(ctrl, data_out, data_out_len);

	pem_destruct_pem_ctrl(ctrl);

	DBG("use_pem_walker_provided_by_ppem() end")
}

int main(int argc, char **argv)
{
	unsigned char *bufin = NULL;
	unsigned char *bufout = NULL;

	parse_options(argc, argv);

	do {
		ssize_t bufin_len = file_size(file_in);
		if (bufin_len < 0) {
			fprintf(stderr, "Unable to get size of file %s", file_in);
			break;
		}

		bufin = malloc(bufin_len + 1);
		FILE *fin;
		if (!(fin = fopen(file_in, "rb"))) {
			fprintf(stderr, "Unable to open file %s for input", file_in);
			break;
		}

		if ((ssize_t)fread(bufin, 1, bufin_len, fin) != bufin_len) {
			fprintf(stderr, "Could not read all data of file %s", file_in);
			break;
		}
		bufin[bufin_len] = '\0';

		fclose(fin);

		size_t bufout_len = 0;

		if (opt_walker)
			use_my_own_pem_walker(bufin, &bufout, &bufout_len);
		else
			use_pem_walker_provided_by_ppem(bufin, &bufout, &bufout_len);

		fprintf(stderr, "Output data length: %lu\n", bufout_len);

		FILE *fout;
		if (!file_out)
			fout = stdout;
		else if (!(fout = fopen(file_out, "wb"))) {
			fprintf(stderr, "Unable to open file %s for output", file_out);
			break;
		}
		if (fwrite(bufout, 1, bufout_len, fout) != bufout_len) {
			fprintf(stderr, "Could not write all data to file %s", !file_out ? "(stdout)" : file_out);
			break;
		}
		if (file_out)
			fclose(fout);
	} while (0);

	free(bufout);
	free(bufin);
}

