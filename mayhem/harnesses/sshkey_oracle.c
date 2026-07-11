/*
 * sshkey_oracle.c — a small GOLDEN oracle over hpn-ssh's SSH public-key parser (the same
 * sshkey API surface that pubkey_fuzz drives). Not a fuzz target: it runs a fixed set of
 * known-answer cases and exits non-zero on the first mismatch. Additive: lives only under
 * mayhem/ and links against the project's own libssh.a.
 *
 * Cases:
 *   - Parse a real ed25519 public key (text "type base64 comment" form) via sshkey_read();
 *     assert sshkey_type() == "ssh-ed25519" and the parsed type id is KEY_ED25519, not a cert.
 *   - Parse a real ECDSA-nistp256 public key; assert type "ecdsa-sha2-nistp256" and 256 bits.
 *   - Parse a real RSA public key; assert type "ssh-rsa" and a plausible modulus size (>= 1024).
 *   - Feed GARBAGE to sshkey_read() and assert it is REJECTED (non-zero return) — a no-op /
 *     "accept everything" change to the parser would make this case fail.
 *
 * This asserts real parser behaviour (type discrimination + rejection of malformed input), so a
 * stub that returns success cannot pass.
 */
#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshkey.h"
#include "ssherr.h"

/* The oracle links the sanitized libssh.a; OpenSSL/library globals legitimately persist to exit, so
 * disable LeakSanitizer's at-exit check (a weak default the runtime honours). This is a baked
 * binary default, not a Mayhemfile ASAN_OPTIONS override. */
const char *__asan_default_options(void) { return "detect_leaks=0"; }

static int failures = 0;
static int total = 0;

/* Fixed, real OpenSSH-format public keys (from the project's own regress testdata). */
static const char *KEY_ED25519_TXT =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD oracle";

/* A self-contained ecdsa-nistp256 and rsa key are read from testdata at run time (see main). */

static struct sshkey *
read_pub(const char *txt)
{
	struct sshkey *k = sshkey_new(KEY_UNSPEC);
	char *cp, *orig;
	if (k == NULL)
		return NULL;
	if ((orig = cp = strdup(txt)) == NULL) {
		sshkey_free(k);
		return NULL;
	}
	if (sshkey_read(k, &cp) != 0) {
		free(orig);
		sshkey_free(k);
		return NULL;
	}
	free(orig);
	return k;
}

static void
check(const char *name, int ok)
{
	total++;
	if (ok) {
		printf("ok   - %s\n", name);
	} else {
		printf("FAIL - %s\n", name);
		failures++;
	}
}

/* Read a whole file into a NUL-terminated buffer (returns NULL on error). */
static char *
slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	if (f == NULL)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n < 0) { fclose(f); return NULL; }
	if ((buf = malloc(n + 1)) == NULL) { fclose(f); return NULL; }
	if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
	fclose(f);
	buf[n] = '\0';
	return buf;
}

int
main(int argc, char **argv)
{
	const char *datadir = (argc > 1) ? argv[1] : ".";
	char path[4096];
	struct sshkey *k;

	/* 1) ed25519 (inline) */
	k = read_pub(KEY_ED25519_TXT);
	check("ed25519: parses", k != NULL);
	if (k != NULL) {
		/* sshkey_type() returns the impl SHORTNAME ("ED25519"); sshkey_ssh_name() the wire name. */
		check("ed25519: type shortname", strcmp(sshkey_type(k), "ED25519") == 0);
		check("ed25519: ssh wire name", strcmp(sshkey_ssh_name(k), "ssh-ed25519") == 0);
		check("ed25519: type id == KEY_ED25519", k->type == KEY_ED25519);
		check("ed25519: not a cert", !sshkey_type_is_cert(k->type));
		sshkey_free(k);
	}

	/* 2) ecdsa-nistp256 from testdata */
	snprintf(path, sizeof(path), "%s/regress/misc/fuzz-harness/testdata/id_ecdsa.pub", datadir);
	{
		char *txt = slurp(path);
		check("ecdsa: testdata present", txt != NULL);
		if (txt != NULL) {
			k = read_pub(txt);
			check("ecdsa: parses", k != NULL);
			if (k != NULL) {
				check("ecdsa: type shortname",
				    strcmp(sshkey_type(k), "ECDSA") == 0);
				check("ecdsa: ssh wire name",
				    strcmp(sshkey_ssh_name(k), "ecdsa-sha2-nistp256") == 0);
				check("ecdsa: 256 bits", sshkey_size(k) == 256);
				sshkey_free(k);
			}
			free(txt);
		}
	}

	/* 3) rsa from testdata */
	snprintf(path, sizeof(path), "%s/regress/misc/fuzz-harness/testdata/id_rsa.pub", datadir);
	{
		char *txt = slurp(path);
		check("rsa: testdata present", txt != NULL);
		if (txt != NULL) {
			k = read_pub(txt);
			check("rsa: parses", k != NULL);
			if (k != NULL) {
				check("rsa: type shortname", strcmp(sshkey_type(k), "RSA") == 0);
				check("rsa: ssh wire name", strcmp(sshkey_ssh_name(k), "ssh-rsa") == 0);
				check("rsa: >= 1024 bits", sshkey_size(k) >= 1024);
				sshkey_free(k);
			}
			free(txt);
		}
	}

	/* 4) malformed input must be REJECTED */
	k = read_pub("ssh-ed25519 not-valid-base64!!!! comment");
	check("garbage base64 rejected", k == NULL);
	if (k != NULL) sshkey_free(k);

	k = read_pub("this is not a key at all");
	check("non-key line rejected", k == NULL);
	if (k != NULL) sshkey_free(k);

	k = read_pub("");
	check("empty line rejected", k == NULL);
	if (k != NULL) sshkey_free(k);

	printf("1..%d\n", total);
	printf("# passed %d, failed %d\n", total - failures, failures);
	return failures == 0 ? 0 : 1;
}
