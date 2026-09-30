#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# bench.sh - re-measure kcov-dataflow overhead.
#
# The numbers in paper/arxiv/main.tex were taken on linux-next 7.1.0-rc6 with
# clang/LLVM 23, against a micro-benchmark module that no longer exists in the
# tree, and they predate the current callback ABI: scalars now reach the
# collector in a register instead of being spilled to an alloca, and the
# callbacks lost their pc operand. Both changes move the per-call cost, so the
# old figures are an upper bound rather than a result. This script reproduces
# the two measurements from scratch and prints them in a form that can be
# pasted straight into the paper.
#
# Two stages, independent:
#
#   micro   Cost of *recording*, on a kernel where only the module under test
#           is instrumented (INSTRUMENT_ALL=n -- with it on, one trigger write
#           records every function on the syscall path and the figure is no
#           longer about the module). Drives eight_struct_args_c's debugfs
#           trigger in a loop with collection off, then on, and divides the
#           difference by the number of records actually captured, so
#           ns/record comes from a counted population rather than a static
#           guess at how many calls a trigger makes.
#
#   global  Cost of instrumenting the whole kernel with collection *disabled*:
#           the idle state a fuzzing host sits in. Builds the kernel twice,
#           INSTRUMENT_ALL off then on, and compares vmlinux section sizes,
#           boot image size, time to userspace, and syscall latency. Expensive:
#           two full builds, done in-tree one after the other, so the tree is
#           left configured as whichever variant ran last.
#
#   ./bench.sh                  # both stages
#   ./bench.sh micro            # just the callback cost
#   ./bench.sh global           # just the whole-kernel cost
#
# Options:
#   -n N        iterations per timed run (default: 5000). The run is capped to
#               what the record buffer holds; the actual count is reported.
#   -b WORDS    record buffer size in u64 words (default: 16777216 = 128MB)
#   -m SIZE     guest memory, passed to vng (default: 4G)
#   -r N        timed runs; the best is reported (default: 3)
#   -o FILE     write the results file here (default: bench-<date>.txt)
#   -j N        build parallelism (default: nproc)
#   -K          do not configure or build a kernel; require that the tree is
#               already built as the variant the stage needs
#   -h          this help
#
# Requires the toolchain rebuild-kselftest.sh produces: clang/lld with the
# trace-args/trace-ret passes, and (for Rust) a matching rustc. Run
# ./rebuild-kselftest.sh llvm rust first if the pass changed.
#
# Honest-measurement notes, because they decide whether the output is usable:
#
#   - Without KVM the guest runs under TCG and every timing below is
#     meaningless as an absolute. The script records which it got and refuses
#     to emit paper-ready rows under TCG.
#   - The micro stage compares recording-off against recording-on in the *same
#     kernel*, so it isolates the collector, not the instrumentation. The
#     global stage is the one that measures instrumentation.
#   - Best-of-N after a warmup run, matching how the original numbers were
#     taken, so the two are comparable.
#
set -o pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LLVM_DIR=$ROOT/llvm-project
RUST_DIR=$ROOT/rust
LINUX_DIR=$ROOT/linux
SELFTESTS=$LINUX_DIR/tools/testing/selftests/kcov_dataflow

die() { printf '\n*** %s\n' "$*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }

ITERS=5000
RUNS=3
BUF_WORDS=$((1 << 24))
GUEST_MEM=4G
JOBS=$(nproc)
RESULTS=
SKIP_BUILD=0
STAGES=()

usage() { sed -n '3,/^set -o/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//;$d'; exit 0; }

while [[ $# -gt 0 ]]; do
	case $1 in
	-n) ITERS=${2?-n needs a value}; shift 2 ;;
	-b) BUF_WORDS=${2?-b needs a value}; shift 2 ;;
	-m) GUEST_MEM=${2?-m needs a value}; shift 2 ;;
	-r) RUNS=${2?-r needs a value}; shift 2 ;;
	-o) RESULTS=${2?-o needs a FILE}; shift 2 ;;
	-j) JOBS=${2?-j needs a value}; shift 2 ;;
	-K) SKIP_BUILD=1; shift ;;
	-h|--help) usage ;;
	-*) die "unknown option '$1'; -h for help" ;;
	micro|global) STAGES+=("$1"); shift ;;
	*) die "unknown stage '$1'; expected micro or global" ;;
	esac
done
[[ ${#STAGES[@]} -eq 0 ]] && STAGES=(micro global)
[[ -n $RESULTS ]] || RESULTS=$ROOT/bench-$(date +%Y%m%d-%H%M%S).txt
# Absolute, always: build_variant() and stage_micro() cd into the kernel tree
# without a subshell, so a relative path from -o would have emit() append to
# linux/<file> for everything written after the first build -- which is exactly
# how the first global run split its provenance and its results in two.
[[ $RESULTS == /* ]] || RESULTS=$PWD/$RESULTS

wants() { [[ " ${STAGES[*]} " == *" $1 "* ]]; }

case $(uname -m) in
x86_64)		RUST_TARGET=x86_64-unknown-linux-gnu; BOOTIMG=arch/x86/boot/bzImage ;;
aarch64|arm64)	RUST_TARGET=aarch64-unknown-linux-gnu; BOOTIMG=arch/arm64/boot/Image ;;
*)		die "unsupported host architecture: $(uname -m)" ;;
esac

export PATH="$LLVM_DIR/build/bin:$PATH"
export RUSTC="$RUST_DIR/build/$RUST_TARGET/stage1/bin/rustc"
export RUST_LIB_SRC="$RUST_DIR/library"

if ! command -v vng >/dev/null 2>&1; then
	for venv in "$ROOT"/venv-virtme "$ROOT"/../venv-virtme "$HOME"/venv-virtme; do
		[[ -f $venv/bin/activate ]] && { . "$venv/bin/activate"; break; }
	done
fi
command -v vng >/dev/null 2>&1 || die "virtme-ng (vng) not found"
command -v clang >/dev/null 2>&1 || die "clang not on PATH"

if [[ -w /dev/kvm ]]; then
	ACCEL=kvm
else
	ACCEL=tcg
	say "WARNING: no /dev/kvm -- running under TCG."
	say "         Timings will be recorded but are NOT usable as absolutes."
fi

# ---------------------------------------------------------------- provenance
#
# Every number below is only interpretable together with what produced it, and
# the whole reason this script exists is that the paper's figures outlived
# their toolchain. Capture it first, into the results file, so the two can
# never drift apart again.
emit() { printf '%s\n' "$*" >> "$RESULTS"; }

: > "$RESULTS"
emit "kcov-dataflow benchmark"
emit "date:     $(date -Is)"
emit "host:     $(uname -srm), ${ACCEL}, $(nproc) cpus"
emit "clang:    $(clang --version | head -1)"
if [[ -x $RUSTC ]]; then
	emit "rustc:    $("$RUSTC" --version 2>/dev/null)"
else
	emit "rustc:    not built (Rust modules unavailable)"
fi
emit "llvm:     $(git -C "$LLVM_DIR" rev-parse --short HEAD 2>/dev/null) on $(git -C "$LLVM_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)"
emit "linux:    $(git -C "$LINUX_DIR" rev-parse --short HEAD 2>/dev/null) on $(git -C "$LINUX_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)"
emit "version:  $(make -C "$LINUX_DIR" -s kernelversion 2>/dev/null)"
emit "params:   iters=$ITERS (max) runs=$RUNS (best of) buffer=$BUF_WORDS words"
emit ""

# ------------------------------------------------------------ guest programs
#
# Generated rather than committed: they are only meaningful alongside this
# script's driving logic, and keeping them here means one file to read.
WORK=$(mktemp -d /tmp/kcov-df-bench.XXXXXX) || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

# df_micro: time N trigger writes with collection off, then on, and count the
# records the on-phase actually produced.
#
# The trigger is a debugfs write, so each iteration is one write() syscall into
# an instrumented module. Collection off still pays for the callback *call* and
# its early return, which is the point: the delta is the cost of a record being
# stored, and that is what the paper's table reports.
#
# The buffer has to be sized before it can be used, but how many records an
# iteration produces is not known in advance: under INSTRUMENT_ALL a single
# write() records every kernel function on the syscall path, not just the
# module's. So probe first on a throwaway fd, then pick an iteration count that
# fits. A buffer that fills mid-run would stop storing and quietly turn the
# measurement into the no-recording case.
cat > "$WORK/df_micro.c" << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kcov_dataflow.h>

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* One iteration: a single write to the module's trigger. */
static int spin(int trig, unsigned long iters)
{
	for (unsigned long i = 0; i < iters; i++)
		if (write(trig, "1", 1) < 0)
			return -1;
	return 0;
}

struct session {
	int fd;
	uint64_t *buf;
	unsigned long words;
};

static int session_open(struct session *s, unsigned long words)
{
	s->words = words;
	s->fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
	if (s->fd < 0) {
		fprintf(stderr, "open(kcov_dataflow): %s\n", strerror(errno));
		return -1;
	}
	if (ioctl(s->fd, KCOV_DF_INIT_TRACK, words)) {
		fprintf(stderr, "ioctl(INIT_TRACK, %lu): %s\n", words,
			strerror(errno));
		return -1;
	}
	s->buf = mmap(NULL, words * sizeof(uint64_t), PROT_READ | PROT_WRITE,
		      MAP_SHARED, s->fd, 0);
	if (s->buf == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	return 0;
}

static void session_close(struct session *s)
{
	munmap(s->buf, s->words * sizeof(uint64_t));
	close(s->fd);
}

struct tally {
	unsigned long all, entry, ret, cmp;
};

/*
 * Walk the buffer and tally records by type. The breakdown matters: with
 * CONFIG_KCOV_ENABLE_COMPARISONS the comparison callbacks fan into this same
 * buffer, and under CONFIG_KCOV_INSTRUMENT_ALL they come from the whole kernel,
 * so they can outnumber the module's arg/ret records by orders of magnitude.
 * Reporting one aggregate count would hide that entirely.
 */
static void count_records(const uint64_t *buf, unsigned long n,
			  struct tally *t)
{
	unsigned long pos = 1;

	memset(t, 0, sizeof(*t));
	while (pos < 1 + n) {
		uint64_t hdr = buf[pos];
		uint32_t nv = KCOV_DF_HDR_NVALS(hdr);

		if (!nv)
			break;
		switch (KCOV_DF_HDR_TYPE(hdr)) {
		case KCOV_DF_TYPE_ENTRY:	t->entry++; break;
		case KCOV_DF_TYPE_RET:		t->ret++;   break;
		case KCOV_DF_TYPE_CMP:		t->cmp++;   break;
		default:			break;
		}
		t->all++;
		pos += KCOV_DF_RECORD_WORDS(nv);
	}
}

/* Returns words consumed by @iters iterations, or 0 on failure. Sets *filled
 * when the buffer ran out, which makes the figure a floor rather than a count.
 */
static unsigned long probe_words(int trig, unsigned long words,
				 unsigned long iters, int *filled)
{
	struct session s;
	unsigned long n;

	*filled = 0;
	if (session_open(&s, words))
		return 0;
	__atomic_store_n(&s.buf[0], 0, __ATOMIC_RELAXED);
	if (ioctl(s.fd, KCOV_DF_ENABLE, 0)) {
		perror("ioctl(ENABLE)");
		return 0;
	}
	if (spin(trig, iters)) {
		perror("write(trigger)");
		return 0;
	}
	ioctl(s.fd, KCOV_DF_DISABLE, 0);
	n = __atomic_load_n(&s.buf[0], __ATOMIC_RELAXED);
	if (n + 8 >= words)
		*filled = 1;
	session_close(&s);
	return n;
}

int main(int argc, char **argv)
{
	unsigned long want  = argc > 1 ? strtoul(argv[1], NULL, 0) : 5000;
	unsigned long runs  = argc > 2 ? strtoul(argv[2], NULL, 0) : 3;
	unsigned long words = argc > 3 ? strtoul(argv[3], NULL, 0) : (1UL << 24);
	const char *trigger = argc > 4 ? argv[4]
		: "/sys/kernel/debug/kcov_dataflow_test/trigger_struct";
	unsigned long iters, probe_iters = 8, pw, stored = 0;
	double off = 1e30, on = 1e30, wpi;
	struct tally tal = { 0 };
	struct session s;
	int trig, filled;

	trig = open(trigger, O_WRONLY);
	if (trig < 0) {
		fprintf(stderr, "open(%s): %s\n", trigger, strerror(errno));
		return 1;
	}

	/* Warmup: fault in text and warm caches before anything is timed. */
	if (spin(trig, want / 10 + 1)) {
		perror("write(trigger)");
		return 1;
	}

	/*
	 * Size the run to the buffer. If even the probe overflows, the kernel
	 * is recording far more per iteration than a per-module build would --
	 * almost always CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y, where a single
	 * write() records every function on the syscall path. That is a
	 * different measurement (the global stage covers it), so refuse rather
	 * than report a per-module figure that is nothing of the kind.
	 */
	pw = probe_words(trig, words, probe_iters, &filled);
	if (!pw) {
		fprintf(stderr, "probe captured nothing\n");
		return 1;
	}
	if (filled) {
		fprintf(stderr,
			"probe of %lu iterations filled a %lu-word buffer.\n"
			"This looks like a whole-kernel instrumented build; the\n"
			"micro stage needs KCOV_DATAFLOW_INSTRUMENT_ALL=n so that\n"
			"only the module under test is instrumented.\n",
			probe_iters, words);
		return 3;
	}
	wpi = (double)pw / probe_iters;
	iters = (unsigned long)((words - 1) * 0.8 / wpi);
	if (iters > want)
		iters = want;
	if (!iters) {
		fprintf(stderr,
			"one iteration needs ~%.0f words; buffer of %lu is too small\n",
			wpi, words);
		return 1;
	}

	if (session_open(&s, words))
		return 1;

	/* Phase A: instrumented code, collection disabled. */
	for (unsigned long r = 0; r < runs; r++) {
		double t0 = now_us(), d;

		if (spin(trig, iters))
			return perror("write(trigger)"), 1;
		d = now_us() - t0;
		if (d < off)
			off = d;
	}

	/* Phase B: same code, collection enabled. */
	for (unsigned long r = 0; r < runs; r++) {
		double t0, d;
		unsigned long n;

		__atomic_store_n(&s.buf[0], 0, __ATOMIC_RELAXED);
		if (ioctl(s.fd, KCOV_DF_ENABLE, 0)) {
			perror("ioctl(ENABLE)");
			return 1;
		}
		t0 = now_us();
		if (spin(trig, iters))
			return perror("write(trigger)"), 1;
		d = now_us() - t0;
		if (ioctl(s.fd, KCOV_DF_DISABLE, 0)) {
			perror("ioctl(DISABLE)");
			return 1;
		}
		n = __atomic_load_n(&s.buf[0], __ATOMIC_RELAXED);
		if (n + 8 >= words) {
			fprintf(stderr,
				"buffer filled at run %lu (%lu/%lu words): "
				"raise the buffer or lower -n\n",
				r, n, words);
			return 2;
		}
		if (d < on) {
			on = d;
			stored = n;
			count_records(s.buf, n, &tal);
		}
	}
	session_close(&s);

	printf("iters_requested  %lu\n", want);
	printf("iters_used       %lu\n", iters);
	printf("buffer_words     %lu\n", words);
	printf("words_per_iter   %.1f\n", wpi);
	printf("off_us_total     %.1f\n", off);
	printf("on_us_total      %.1f\n", on);
	printf("off_us_iter      %.4f\n", off / iters);
	printf("on_us_iter       %.4f\n", on / iters);
	printf("overhead_pct     %.2f\n", (on - off) / off * 100.0);
	printf("words            %lu\n", stored);
	printf("records          %lu\n", tal.all);
	printf("records_entry    %lu\n", tal.entry);
	printf("records_ret      %lu\n", tal.ret);
	printf("records_cmp      %lu\n", tal.cmp);
	printf("records_iter     %.2f\n", (double)tal.all / iters);
	printf("argret_iter      %.2f\n",
	       (double)(tal.entry + tal.ret) / iters);
	if (tal.all)
		printf("ns_per_record    %.2f\n",
		       (on - off) * 1000.0 / tal.all);
	printf("buffer_filled    no\n");
	return 0;
}
EOF

# df_syscall: syscall latency, for the global stage. Instrumentation is
# kernel-wide there, so an ordinary syscall mix is the thing to time; the
# module trigger would only measure one module.
cat > "$WORK/df_syscall.c" << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/uio.h>

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

int main(int argc, char **argv)
{
	unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 0) : 5000;
	unsigned long runs  = argc > 2 ? strtoul(argv[2], NULL, 0) : 3;
	double best = 1e30;
	char buf[64];
	struct stat st;
	int fd;

	/*
	 * A mix that crosses a decent amount of kernel text -- VFS lookup,
	 * read, seek, stat -- so whole-kernel instrumentation shows up. A
	 * single getpid() would mostly measure the syscall entry stub.
	 */
	for (unsigned long r = 0; r < runs + 1; r++) {
		double t0 = now_us(), d;

		for (unsigned long i = 0; i < iters; i++) {
			fd = open("/proc/self/stat", O_RDONLY);
			if (fd < 0)
				return perror("open"), 1;
			if (read(fd, buf, sizeof(buf)) < 0)
				return perror("read"), 1;
			if (fstat(fd, &st) < 0)
				return perror("fstat"), 1;
			lseek(fd, 0, SEEK_SET);
			close(fd);
		}
		d = now_us() - t0;
		if (r && d < best)	/* r == 0 is the warmup */
			best = d;
	}
	printf("syscall_us_iter  %.4f\n", best / iters);
	return 0;
}
EOF

build_guest_progs() {
	local inc=$1

	clang -O2 -static -I"$inc" -o "$WORK/df_micro" "$WORK/df_micro.c" || return 1
	clang -O2 -static -o "$WORK/df_syscall" "$WORK/df_syscall.c" || return 1
}

# ----------------------------------------------------------------- variants
#
# Both stages need kernels that differ only in
# CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL, and the builds have to happen in-tree:
# this tree already has an in-tree build, and kbuild refuses a separate O=
# output directory until "make mrproper" has cleaned that up, which would throw
# away the existing kernel. So configure, build, measure, then reconfigure --
# sequentially, caching each variant's static numbers so a rerun of one stage
# does not rebuild the other.
#
# Consequence worth stating: when this finishes, the tree is left configured as
# whichever variant ran last.
VARIANT_CACHE=$ROOT/.bench-obj
mkdir -p "$VARIANT_CACHE"

configured_variant() {
	grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' "$LINUX_DIR/.config" \
		2>/dev/null && { echo y; return; }
	grep -q '^CONFIG_KCOV_DATAFLOW_ARGS=y' "$LINUX_DIR/.config" \
		2>/dev/null && { echo n; return; }
	echo unknown
}

# Configure the tree for INSTRUMENT_ALL=$1 and build it.
build_variant() {
	local instrument_all=$1
	# KASAN is pinned, not inherited: the comparison against the kernel
	# sanitizers only means anything if both variants carry it, so that the
	# reported overhead is the cost added to an already-sanitized kernel.
	local -a want=(KCOV KCOV_DATAFLOW_ARGS KCOV_DATAFLOW_RET
		       KASAN DEBUG_INFO_DWARF5 DEBUG_FS MODULES)
	local -a mk=(LLVM=1 CC=clang)
	local c missing=()

	cd "$LINUX_DIR" || return 1
	[[ -x $RUSTC ]] && mk+=(RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC")

	# --no-update keeps an existing bootable config, so the per-variant
	# edits below are not thrown away on a rerun.
	virtme-configkernel --defconfig --no-update || return 1

	./scripts/config --disable DEBUG_INFO_NONE --disable DEBUG_INFO_REDUCED
	for c in "${want[@]}"; do
		./scripts/config --enable "$c" || return 1
	done
	if [[ $instrument_all == y ]]; then
		./scripts/config --enable KCOV_DATAFLOW_INSTRUMENT_ALL || return 1
	else
		./scripts/config --disable KCOV_DATAFLOW_INSTRUMENT_ALL || return 1
	fi
	# -fno-inline would change the number of boundaries, which is a
	# different experiment; keep it off in both variants so the only
	# difference is what gets instrumented.
	./scripts/config --disable KCOV_DATAFLOW_NO_INLINE
	# Pinned on rather than inherited, for two reasons. It is the realistic
	# fuzzing configuration, and more practically it cannot be turned off
	# incrementally: objects already built with the cmp callbacks are not
	# rebuilt when the option flips, and vmlinux then fails to link against
	# __sanitizer_cov_trace_cmp8, which kcov.c only defines when the option
	# is on. Pinning it means the build is always consistent with the
	# config whichever order the stages run in. Comparison records share
	# the dataflow buffer via kcov_df_trace_cmp(), so df_micro tallies
	# records by type and reports the arg/ret population separately.
	./scripts/config --enable KCOV_ENABLE_COMPARISONS
	./scripts/config --enable KCOV_INSTRUMENT_ALL
	make "${mk[@]}" -s olddefconfig || return 1

	for c in "${want[@]}"; do
		grep -q "^CONFIG_$c=y\$" .config || missing+=("$c")
	done
	grep -q "^CONFIG_KCOV_DATAFLOW_NO_INLINE=y\$" .config &&
		missing+=("!KCOV_DATAFLOW_NO_INLINE")
	if [[ ${#missing[@]} -gt 0 ]]; then
		say "these did not take: ${missing[*]}"
		say "(CONFIG_KCOV_DATAFLOW_* need a clang carrying the passes)"
		return 1
	fi
	if [[ $(configured_variant) != "$instrument_all" ]]; then
		say "INSTRUMENT_ALL=$instrument_all did not take"
		return 1
	fi

	make "${mk[@]}" -j "$JOBS" || return 1
	make "${mk[@]}" -j "$JOBS" modules || return 1
}

# Make sure the tree is built as $1, reusing it if it already is.
ensure_variant() {
	local v=$1

	if [[ $SKIP_BUILD -eq 1 ]]; then
		if [[ $(configured_variant) == "$v" && -f $LINUX_DIR/vmlinux ]]; then
			say "reusing the in-tree build (INSTRUMENT_ALL=$v)"
			return 0
		fi
		die "-K given but the tree is not built with INSTRUMENT_ALL=$v"
	fi
	say "building kernel with INSTRUMENT_ALL=$v"
	build_variant "$v"
}

# ------------------------------------------------------------- stage: micro
#
# The paper's micro-benchmark is per-module: a handful of instrumented
# functions driven in a loop. That needs INSTRUMENT_ALL=n -- with it on, one
# trigger write records every kernel function on the syscall path and the
# figure stops being about the module at all. The guest program refuses that
# case rather than reporting it.
stage_micro() {
	local out inc=$LINUX_DIR/usr/include
	local -a mk=(LLVM=1 CC=clang) vngargs

	ensure_variant n || return 1
	cd "$LINUX_DIR" || return 1

	say "micro: building uapi headers and the test module"
	make "${mk[@]}" -s headers || return 1
	make "${mk[@]}" -j "$JOBS" \
		M="$SELFTESTS/eight_struct_args_c" modules || return 1

	[[ -f $SELFTESTS/eight_struct_args_c/eight_struct_args_c.ko ]] ||
		die "micro: eight_struct_args_c.ko missing"
	[[ -f $inc/linux/kcov_dataflow.h ]] ||
		die "micro: $inc/linux/kcov_dataflow.h missing"
	build_guest_progs "$inc" || return 1

	vngargs=(--verbose --user root --cpus "$(nproc)" --memory "$GUEST_MEM")

	say "micro: timing in the guest (up to $ITERS iters, best of $RUNS)"
	out=$WORK/micro.out
	vng "${vngargs[@]}" --exec "
		set -e
		mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
		insmod $SELFTESTS/eight_struct_args_c/eight_struct_args_c.ko
		$WORK/df_micro $ITERS $RUNS $BUF_WORDS
		rmmod eight_struct_args_c
	" > "$out" 2>&1 || true

	if grep -q "looks like a whole-kernel instrumented build" "$out"; then
		say "micro: the guest kernel instruments everything"
		sed -n "/^probe of/,/^only the module/p" "$out"
		return 1
	fi
	grep -qE "^records +[1-9]" "$out" || {
		say "micro: no records captured"
		sed -n "1,40p" "$out"
		return 1
	}

	emit "=== micro: cost of recording (one kernel, collection off vs on) ==="
	emit "    KCOV_DATAFLOW_INSTRUMENT_ALL=n: only eight_struct_args_c carries"
	emit "    arg/ret instrumentation. Records are tallied by type, because"
	emit "    CONFIG_KCOV_ENABLE_COMPARISONS fans cmp records into this same"
	emit "    buffer from wherever trace-cmp is enabled."
	grep -E "^(iters_requested|iters_used|buffer_words|words_per_iter|off_us_iter|on_us_iter|overhead_pct|records|records_entry|records_ret|records_cmp|records_iter|argret_iter|ns_per_record) " "$out" >> "$RESULTS"
	emit ""
	paper_micro "$out"
	sed -n "/^iters_requested/,/^buffer_filled/p" "$out"
}

# ------------------------------------------------------------ stage: global
#
# Cost of instrumenting the whole kernel with collection disabled: the idle
# state a fuzzing host sits in. Static numbers come from the build, runtime
# numbers from a guest boot of it.
probe_variant() {
	local tag=$1 out=$WORK/$tag.probe
	local text data img boot sysc

	# Keep the whole section table per variant: the first run of this stage
	# reported .data at +0% and had no .rodata row, so the section that
	# actually grows -- the field tables are constant globals -- was the one
	# not being measured. Saving the table means a later question about a
	# different section does not cost another pair of kernel builds.
	size -A "$LINUX_DIR/vmlinux" > "$VARIANT_CACHE/$tag.sections"
	text=$(awk '$1==".text"{print $2}'   "$VARIANT_CACHE/$tag.sections")
	data=$(awk '$1==".data"{print $2}'   "$VARIANT_CACHE/$tag.sections")
	rodata=$(awk '$1==".rodata"{print $2}' "$VARIANT_CACHE/$tag.sections")
	img=$(stat -c %s "$LINUX_DIR/$BOOTIMG" 2>/dev/null || echo 0)

	# Time to userspace from the guest's own clock, so host-side vng
	# startup is excluded.
	( cd "$LINUX_DIR" && vng --verbose --user root --cpus "$(nproc)" \
		--memory "$GUEST_MEM" --exec "
		set -e
		printf 'boot_s           %s\n' \$(cut -d' ' -f1 /proc/uptime)
		$WORK/df_syscall $ITERS $RUNS
	" ) > "$out" 2>&1 || { sed -n "1,40p" "$out"; return 1; }

	boot=$(awk '/^boot_s/{print $2}' "$out")
	sysc=$(awk '/^syscall_us_iter/{print $2}' "$out")
	[[ -n $sysc && -n $boot ]] || {
		say "global: $tag produced no timing"
		sed -n "1,40p" "$out"
		return 1
	}
	printf '%s %s %s %s %s %s\n' "$text" "$data" "$rodata" "$img" \
		"$boot" "$sysc" > "$VARIANT_CACHE/$tag.nums"
}

stage_global() {
	local b i

	clang -O2 -static -o "$WORK/df_syscall" "$WORK/df_syscall.c" || return 1

	ensure_variant n || return 1
	say "global: probing baseline (INSTRUMENT_ALL=n)"
	probe_variant base || return 1

	ensure_variant y || return 1
	say "global: probing INSTRUMENT_ALL=y"
	probe_variant instrument-all || return 1

	b=$(cat "$VARIANT_CACHE/base.nums")
	i=$(cat "$VARIANT_CACHE/instrument-all.nums")

	emit "=== global: whole-kernel instrumentation, collection disabled ==="
	emit "metric              baseline        INSTRUMENT_ALL  overhead"
	emit "(full section tables: $VARIANT_CACHE/{base,instrument-all}.sections)"
	paper_global "$b" "$i" | tee -a "$RESULTS"
}

# --------------------------------------------------------------- reporting
#
# The point of the run is to replace numbers in the paper, so print rows that
# can be pasted in, and refuse to under TCG rather than emitting figures that
# look authoritative and are not.
paper_micro() {
	local out=$1 offi oni pct nspr rpi

	offi=$(awk '/^off_us_iter/{print $2}' "$out")
	oni=$(awk '/^on_us_iter/{print $2}' "$out")
	pct=$(awk '/^overhead_pct/{print $2}' "$out")
	nspr=$(awk '/^ns_per_record/{print $2}' "$out")
	rpi=$(awk '/^records_iter/{print $2}' "$out")
	local ari cmp
	ari=$(awk '/^argret_iter/{print $2}' "$out")
	cmp=$(awk '/^records_cmp/{print $2}' "$out")

	if [[ $ACCEL != kvm ]]; then
		emit "(TCG run: no paper-ready rows emitted)"
		return
	fi
	# Formatted with awk, not bash's printf: printf '%.1f' rejects a dot
	# decimal under a locale whose LC_NUMERIC uses a comma, which turned
	# every figure into "invalid number" on the first run of this script.
	#
	# The headline number is ns per stored record, not the percentage. The
	# percentage is a property of this workload's record density -- how many
	# boundaries and comparisons one iteration crosses -- and the trigger
	# used here is far denser than the 44-callback loop the paper's old
	# table was built on. Quoting a percentage without its density beside it
	# is what made the old figure impossible to compare against.
	emit "cost per stored record:"
	emit "$(awk -v n="$nspr" 'BEGIN{printf "  %.1f ns", n}')"
	emit "measured on this workload:"
	emit "$(awk -v v="$offi" 'BEGIN{printf "  collection off: %.1f us/iter", v}')"
	emit "$(awk -v v="$oni" 'BEGIN{printf "  collection on:  %.1f us/iter", v}')"
	emit "$(awk -v p="$pct" 'BEGIN{printf "  overhead:       +%.1f%%", p}')"
	emit "$(awk -v r="$rpi" -v a="$ari" -v c="$cmp" 'BEGIN{printf "  density:        %.0f records/iter (%.0f arg+ret, %d cmp total)", r, a, c}')"
	emit ""
	emit "To quote a percentage in the paper, state the density with it: the"
	emit "same per-record cost gives a different percentage on a workload that"
	emit "crosses fewer boundaries per syscall."
	emit ""
}

paper_global() {
	read -r bt bd br bi bb bs <<< "$1"
	read -r it id ir ii ib is <<< "$2"

	pc() { awk -v a="$1" -v b="$2" 'BEGIN{if(a>0)printf "+%.0f%%", (b-a)/a*100; else printf "n/a"}'; }
	mb() { awk -v v="$1" 'BEGIN{printf "%.1f MB", v/1048576}'; }

	printf 'vmlinux .text       %-15s %-15s %s\n' "$(mb "$bt")" "$(mb "$it")" "$(pc "$bt" "$it")"
	printf 'vmlinux .rodata     %-15s %-15s %s\n' "$(mb "$br")" "$(mb "$ir")" "$(pc "$br" "$ir")"
	printf 'vmlinux .data       %-15s %-15s %s\n' "$(mb "$bd")" "$(mb "$id")" "$(pc "$bd" "$id")"
	printf 'boot image          %-15s %-15s %s\n' "$(mb "$bi")" "$(mb "$ii")" "$(pc "$bi" "$ii")"
	printf 'time to userspace   %-15s %-15s %s\n' "${bb}s" "${ib}s" "$(pc "$bb" "$ib")"
	printf 'syscall latency     %-15s %-15s %s\n' "${bs}us/iter" "${is}us/iter" "$(pc "$bs" "$is")"
	if [[ $ACCEL != kvm ]]; then
		printf '(TCG run: size rows are valid, timing rows are not)\n'
	fi
}

# ------------------------------------------------------------------- driver
FAILED=()
wants micro  && { stage_micro  || FAILED+=(micro); }
wants global && { stage_global || FAILED+=(global); }

say "results written to $RESULTS"
if [[ ${#FAILED[@]} -gt 0 ]]; then
	die "failed stages: ${FAILED[*]}"
fi
say "done"
