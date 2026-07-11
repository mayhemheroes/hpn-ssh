#!/usr/bin/env bash
#
# hpn-ssh/mayhem/build.sh — build hpn-ssh's OpenSSH-style fuzz harnesses as sanitized libFuzzer
# targets (+ standalone reproducers). hpn-ssh is an OpenSSH fork; the harnesses live in
# regress/misc/fuzz-harness/ and exercise the SSH KEY / SIGNATURE / KEX / AUTH parsers:
#
#   pubkey_fuzz    — sshkey_from_blob(): parse an SSH public-key blob into a struct sshkey.
#   privkey_fuzz   — sshkey_private_deserialize(): parse a serialized SSH private key.
#   sig_fuzz       — sshkey_verify(): verify an attacker-controlled signature against fixed keys.
#   authopt_fuzz   — sshauthopt_parse()/sshauthopt_merge(): parse authorized_keys options.
#   sshsig_fuzz    — sshsig_verifyb(): verify an SSH signature (the `ssh-keygen -Y` format).
#   sshsigopt_fuzz — sshsigopt_parse(): parse an allowed_signers options line.
#   kex_fuzz       — kex_input_*(): drive the SSH key-exchange state machine on raw packets.
#   agent_fuzz     — ssh-agent request parser (driven via agent_fuzz_helper + sk-dummy).
#
# Build approach mirrors OSS-Fuzz's hpn-ssh build.sh: configure + `make all` builds libssh.a and
# openbsd-compat with $SANITIZER_FLAGS, then each C++ harness is linked against them with crypto
# linked STATICALLY (-Wl,-Bstatic -lcrypto). Security-key (FIDO/U2F) support is stubbed out via
# ssh-sk-null.cc (and sk-dummy.c for the agent), so libfido2/libcbor are NOT required.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile the SSH library ITSELF with $SANITIZER_FLAGS so the parsers
# (not just the harness) are instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS carries DWARF < 4 debug info independently of the sanitizer off-switch. clang-19's
# plain `-g` emits DWARF-5 which Mayhem's triage can't read; -gdwarf-3 is explicit (§6.2 item 10).
# Put DEBUG_FLAGS AFTER SANITIZER_FLAGS in compile lines so -gdwarf-3 wins.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${CFLAGS=}" ; : "${CXXFLAGS=}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX CFLAGS CXXFLAGS LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

OUT=/mayhem
HARNESS_DIR="$SRC/regress/misc/fuzz-harness"

# ── 1) Enable the null cipher + disable agent unlock delay (same tweaks OSS-Fuzz makes so the
#       harnesses can drive every cipher / the agent without artificial sleeps). Idempotent seds. ──
sed -i 's/#define CFLAG_INTERNAL.*/#define CFLAG_INTERNAL 0/' cipher.c || true
sed -i 's|\(usleep.*\)|// \1|' ssh-agent.c || true

# ── 2) Configure + build libssh / openbsd-compat WITH sanitizers ──────────────────────────────────
# Push $SANITIZER_FLAGS through configure so the SSH library code is instrumented. ASan's
# interceptors can trip configure's tiny feature probes (false "broken" results); keep the
# OSS-Fuzz flags (--without-hardening, --without-zlib-version-check) and a -DWITH_XMSS=1 cflag.
# -fsanitize=fuzzer-no-link instruments the SSH library with libFuzzer coverage counters WITHOUT
# pulling in the fuzzer main(); the harness's -fsanitize=fuzzer (LIB_FUZZING_ENGINE) provides the
# runtime. Without this, libFuzzer sees flat coverage (the parsers aren't instrumented). Only added
# when ASan/sanitizers are on (skip for an explicit empty SANITIZER_FLAGS build).
COV_FLAGS=""
[ -n "${SANITIZER_FLAGS}" ] && COV_FLAGS="-fsanitize=fuzzer-no-link"
export COV_FLAGS

# Idempotency guard: autoreconf+configure+make are expensive and non-idempotent (a second configure
# regenerates config.h touching its mtime, which causes make to rebuild sk-usbhid.o — but that
# file needs libfido2 headers which aren't installed). Skip the configure+make block if the tree
# is already built (Makefile + libssh.a both present), so a second offline run is a safe no-op.
if [ -f Makefile ] && [ -f libssh.a ]; then
  echo ">> configure+make: tree already built — skipping (idempotent re-run)"
else
  autoreconf
  env CFLAGS="" ./configure \
      --without-hardening \
      --without-zlib-version-check \
      --with-cflags="-DWITH_XMSS=1" \
      --with-cflags-after="$SANITIZER_FLAGS $COV_FLAGS" \
      --with-ldflags-after="-g $SANITIZER_FLAGS" \
    || { echo "------ config.log:" 1>&2; cat config.log 1>&2; echo "ERROR: configure failed" 1>&2; exit 1; }

  make -j"$MAYHEM_JOBS" all
fi

# ── 3) Build the fuzz harnesses ────────────────────────────────────────────────────────────────────
# CIPHER_NONE_AVAIL=1 enables the null cipher in kex_fuzz; _GNU_SOURCE + openbsd-compat/include for
# the portability shims. SK support is stubbed (ssh-sk-null.o) so no libfido2/libcbor link.
EXTRA_CFLAGS="-DCIPHER_NONE_AVAIL=1 -D_GNU_SOURCE -Iopenbsd-compat/include"
# OSS-Fuzz links crypto statically against its own self-contained libcrypto.a. On the debian base
# the system libcrypto.a is built WITH zstd/brotli BIO support, so a static link pulls in
# unresolved ZSTD_*/Brotli* symbols; link crypto DYNAMICALLY (libcrypto.so.3) to sidestep that.
STATIC_CRYPTO="-lcrypto"

SK_NULL=ssh-sk-null.o
SK_DUMMY=sk-dummy.o
COMMON_DEPS="ssh-pkcs11-client.o -lssh -lopenbsd-compat"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c \
	"$HARNESS_DIR/ssh-sk-null.cc" -o "$SRC/ssh-sk-null.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c \
	-DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o "$SRC/sk-dummy.o"

# Compile each harness twice: once as a libFuzzer target (-> /mayhem/<name>), once as a standalone
# run-once reproducer (-> /mayhem/<name>-standalone) using the base's StandaloneFuzzTargetMain.c.
# build_harness <name> [extra-objs...]
# The standalone main MUST be compiled with the C compiler ($CC) so its reference to
# LLVMFuzzerTestOneInput keeps C linkage (matching the harness's `extern "C"` definition); compiling
# it as part of the C++ link mangles the symbol and the link fails.
STANDALONE_MAIN_SRC="${STANDALONE_FUZZ_MAIN:-/opt/mayhem/StandaloneFuzzTargetMain.c}"
STANDALONE_MAIN_OBJ="$SRC/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_MAIN_SRC" -o "$STANDALONE_MAIN_OBJ"
build_harness() {
  local name="$1"; shift
  local extra_objs="$*"
  echo ">> building $name"
  # libFuzzer target
  $CXX $CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	"$HARNESS_DIR/$name.cc" -o "$OUT/$name" \
	$extra_objs $COMMON_DEPS $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
  # standalone reproducer (no libFuzzer runtime; reads one input file). $COV_FLAGS pulls the minimal
  # coverage runtime so the fuzzer-no-link instrumented library resolves its __sanitizer_cov_* calls.
  $CXX $CXXFLAGS $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	"$HARNESS_DIR/$name.cc" "$STANDALONE_MAIN_OBJ" -o "$OUT/$name-standalone" \
	$extra_objs $COMMON_DEPS $SK_NULL $STATIC_CRYPTO \
	|| echo "WARNING: standalone build for $name failed (libFuzzer target still produced)" >&2
}

build_harness pubkey_fuzz
build_harness privkey_fuzz
build_harness sig_fuzz
build_harness authopt_fuzz "auth-options.o"
build_harness sshsig_fuzz "sshsig.o"
build_harness sshsigopt_fuzz "sshsig.o"

# kex_fuzz also needs zlib
echo ">> building kex_fuzz"
$CXX $CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	"$HARNESS_DIR/kex_fuzz.cc" -o "$OUT/kex_fuzz" \
	$COMMON_DEPS -lz $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	"$HARNESS_DIR/kex_fuzz.cc" "$STANDALONE_MAIN_OBJ" -o "$OUT/kex_fuzz-standalone" \
	$COMMON_DEPS -lz $SK_NULL $STATIC_CRYPTO \
	|| echo "WARNING: standalone build for kex_fuzz failed" >&2

# agent_fuzz: needs the agent helper + sk-dummy + ssh-sk.o (built with ENABLE_SK_INTERNAL).
echo ">> building agent_fuzz"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c \
	"$HARNESS_DIR/agent_fuzz_helper.c" -o "$SRC/agent_fuzz_helper.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o "$SRC/ssh-sk.o"
$CXX $CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	"$HARNESS_DIR/agent_fuzz.cc" -o "$OUT/agent_fuzz" \
	"$SRC/sk-dummy.o" "$SRC/agent_fuzz_helper.o" "$SRC/ssh-sk.o" $COMMON_DEPS -lz \
	$STATIC_CRYPTO $LIB_FUZZING_ENGINE

# ── 4) Build the functional golden oracle (mayhem/test.sh runs it) ─────────────────────────────────
# A known-answer oracle over the sshkey parser (NOT a fuzzing build — no libFuzzer engine). It must
# be built WITH $SANITIZER_FLAGS because it links the project's libssh.a / libopenbsd-compat.a, which
# were compiled with ASan+UBSan above; a plain build leaves the sanitizer runtime symbols undefined.
# Sanitizers don't change the oracle's correctness — it stays an honest known-answer check.
echo ">> building sshkey_oracle"
$CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O2 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	mayhem/harnesses/sshkey_oracle.c -o "$SRC/mayhem-oracle" \
	$COMMON_DEPS $SK_NULL $STATIC_CRYPTO -lz \
  || { echo "ERROR: oracle build failed" >&2; exit 1; }

echo "build.sh complete:"
ls -la "$OUT"/pubkey_fuzz "$OUT"/privkey_fuzz "$OUT"/sig_fuzz "$OUT"/authopt_fuzz \
       "$OUT"/sshsig_fuzz "$OUT"/sshsigopt_fuzz "$OUT"/kex_fuzz "$OUT"/agent_fuzz "$SRC"/mayhem-oracle 2>&1 || true
