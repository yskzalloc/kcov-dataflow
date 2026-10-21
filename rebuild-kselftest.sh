#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# rebuild-kselftest.sh - rebuild the kcov-dataflow toolchain and run the
# kcov_dataflow kselftests in a virtme-ng guest.
#
# Four stages, built in dependency order because each consumes the previous
# one's output:
#
#   llvm      clang/lld carrying the trace-args and trace-ret SanitizerCoverage
#             passes, plus the LLVM libraries rustc links against
#   rust      stage1 rustc built against that LLVM, so Rust kernel modules get
#             the same passes natively
#   linux     the kernel, built with LLVM=1 and the rebuilt rustc
#   selftest  the kselftest programs and out-of-tree test modules, then a
#             virtme-ng boot that runs them, reported the way CI reports them
#
# Touching the pass makes every later stage stale, so by default all of them
# run; name stages to do less:
#
#   ./rebuild-kselftest.sh                   # everything
#   ./rebuild-kselftest.sh linux selftest    # kernel and tests only
#   ./rebuild-kselftest.sh selftest          # just rebuild and re-run tests
#
# Options may appear anywhere, before or after stage names:
#   -j N        parallelism (default: nproc)
#   -k          keep going: report a failing stage but continue
#   -v FILE     write the guest's full output to FILE (default: a temp file)
#   -t NAME     run only this test module, via test_modules.py (repeatable)
#   -o SECONDS  per-target kselftest timeout (default: 600 with KVM, else 1800)
#   -h          this help
#
# The selftest stage mirrors .github/workflows/ci.yml: the same results banner,
# and the same verification. Keep the two in step -- a local pass that CI then
# rejects, or the reverse, is worse than no check at all. What is verified:
#
#   - no target timed out
#   - all three targets reported ok
#   - no case reported "not ok"
#   - rust_ffi_contract and eight_struct_args_c ran: both are unconditional
#     obj-m (both are C), so they are required in every configuration
#   - with CONFIG_RUST=y: eight_struct_args_rust and rust_kworker_remote ran
#     too, and so did binderfs -- the binder driver in this tree is
#     ANDROID_BINDER_IPC_RUST, which "depends on RUST"
#   - without it: those four legitimately SKIP, and the run is reported as not
#     having validated the Rust side
#   - the DWARF source-map checks ran: test_modules.py resolved the records
#     through "sancov -symbolize-dataflow" ($SANCOV), rather than skipping
#     (not checked with the phase-0-5-a toolchain, whose sancov has no
#     -symbolize-dataflow; see report_results)
#
set -o pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LLVM_DIR=$ROOT/llvm-project
# The LLVM build tree whose clang, lld, sancov and llvm-config are used. Point
# it elsewhere to reuse an existing build, e.g. an assertions-enabled one:
#   LLVM_BUILD=$PWD/llvm-project/build-clang ./rebuild-kselftest.sh ...
LLVM_BUILD=${LLVM_BUILD:-$LLVM_DIR/build}
RUST_DIR=$ROOT/rust
LINUX_DIR=$ROOT/linux
KSELFTEST_DIR=$LINUX_DIR/kselftest-install

die() { printf '\n*** %s\n' "$*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }

# Build for whatever this machine is, so the same script works on the arm64
# runner shape as well as locally.
case $(uname -m) in
x86_64)		LLVM_TARGET=X86;     RUST_TARGET=x86_64-unknown-linux-gnu ;;
aarch64|arm64)	LLVM_TARGET=AArch64; RUST_TARGET=aarch64-unknown-linux-gnu ;;
*)		die "unsupported host architecture: $(uname -m)" ;;
esac
STAGE1=$RUST_DIR/build/$RUST_TARGET/stage1

# No KVM means TCG, which is several times slower; the 300s the kcov_dataflow
# settings file asks for is sized for KVM and gets test_modules.py killed part
# way through its module list without it.
if [[ -w /dev/kvm ]]; then
	ACCEL=kvm
	TIMEOUT=600
else
	ACCEL=tcg
	TIMEOUT=1800
fi
LABEL="$(uname -m)/$ACCEL"

JOBS=$(nproc)
KEEP_GOING=0
OUTPUT=
MODULE_FILTER=()
STAGES=()

usage() { sed -n '3,/^set -o/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//;$d'; exit 0; }

# Hand-rolled rather than getopts: getopts stops at the first non-option, so
# "-v log selftest" worked and "selftest -v log" silently ignored the -v.
while [[ $# -gt 0 ]]; do
	case $1 in
	-j) JOBS=${2?-j needs a value}; shift 2 ;;
	-k) KEEP_GOING=1; shift ;;
	-v) OUTPUT=${2?-v needs a FILE}; shift 2 ;;
	-t) MODULE_FILTER+=(-t "${2?-t needs a NAME}"); shift 2 ;;
	-o) TIMEOUT=${2?-o needs SECONDS}; shift 2 ;;
	-h|--help) usage ;;
	-*) die "unknown option '$1'; -h for help" ;;
	llvm|rust|linux|selftest) STAGES+=("$1"); shift ;;
	*) die "unknown stage '$1'; expected llvm, rust, linux or selftest" ;;
	esac
done
[[ ${#STAGES[@]} -eq 0 ]] && STAGES=(llvm rust linux selftest)

wants() { [[ " ${STAGES[*]} " == *" $1 "* ]]; }

for d in "$LLVM_DIR" "$RUST_DIR" "$LINUX_DIR"; do
	[[ -d $d ]] || die "missing tree: $d"
done

# The rebuilt toolchain has to win over anything already installed, and the
# kernel build has to be told which rustc to use.
export PATH="$LLVM_BUILD/bin:$PATH"
export RUSTC="$STAGE1/bin/rustc"
export RUST_LIB_SRC="$RUST_DIR/library"

# virtme-ng usually lives in a venv next to the trees; activate it if vng is
# not already on PATH.
if ! command -v vng >/dev/null 2>&1; then
	for venv in "$ROOT"/venv-virtme "$ROOT"/../venv-virtme "$HOME"/venv-virtme; do
		if [[ -f $venv/bin/activate ]]; then
			# shellcheck disable=SC1091
			source "$venv/bin/activate"
			break
		fi
	done
fi

FAILED=()
run_stage() {
	local name=$1; shift
	say "$name"
	if "$@"; then
		return 0
	fi
	FAILED+=("$name")
	[[ $KEEP_GOING -eq 1 ]] || die "stage '$name' failed"
	return 1
}

# --- llvm ---------------------------------------------------------------
#
# Configure only when the build tree is not there yet, so an incremental run
# after editing a pass is just the ninja call.
build_llvm() {
	if [[ ! -f $LLVM_BUILD/build.ninja ]]; then
		cmake -S "$LLVM_DIR/llvm" -B "$LLVM_BUILD" -G Ninja \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_C_COMPILER=clang \
			-DCMAKE_CXX_COMPILER=clang++ \
			-DLLVM_ENABLE_LLD=ON \
			-DLLVM_ENABLE_PROJECTS="clang;lld" \
			-DLLVM_ENABLE_RUNTIMES="compiler-rt" \
			-DLLVM_TARGETS_TO_BUILD="$LLVM_TARGET" || return 1
	fi
	ninja -C "$LLVM_BUILD" -j "$JOBS" || return 1

	# The pass is what this tree exists for: fail early and loudly if its
	# own tests regressed, rather than at kselftest time.
	# Tests for a target the build does not include report UNSUPPORTED.
	local t=$LLVM_DIR/llvm/test
	local -a lit_tests=(
		"$t/Instrumentation/SanitizerCoverage"
		# Not in the phase-0-5-a toolchain (instrumentation, clang flag,
		# compiler-rt callbacks, docs only): the !pcsections codegen
		# fixes, the DWARF tag, the AArch64 WZR/XZR call-site fix and the
		# sancov dataflow tests come with later steps.
		# "$t/CodeGen/X86/pcsections-per-pc.ll"
		# "$t/CodeGen/X86/pcsections-call.ll"
		# "$t/CodeGen/AArch64/pcsections-per-pc.ll"
		# "$t/CodeGen/AArch64/pcsections-call.ll"
		# "$t/DebugInfo/X86/sancov-observation.ll"
		# "$t/DebugInfo/AArch64/call-site-param-zero-register.ll"
		"$t/tools/sancov"
		"$LLVM_DIR/clang/test/CodeGen/sanitizer-coverage-trace-args-ret.c"
		"$LLVM_DIR/clang/test/Driver/fsanitize-coverage.c"
	)
	"$LLVM_BUILD/bin/llvm-lit" -s "${lit_tests[@]}" || return 1

	# The runtime end to end, under every sanitizer configuration, when the
	# build has compiler-rt (as CI's does). lit finds a suite only from a
	# directory with its own lit.site.cfg.py: one per configuration
	# (asan-<arch>-Linux, ...), not their parent.
	local -a configs
	configs=("$LLVM_BUILD"/runtimes/runtimes-bins/compiler-rt/test/sanitizer_common/*-Linux)
	if [[ -d ${configs[0]} ]]; then
		"$LLVM_BUILD/bin/llvm-lit" -s --filter='sanitizer_coverage_trace_(args|access)' \
			"${configs[@]}"
	else
		say "llvm: no compiler-rt in $LLVM_BUILD; runtime tests not run"
	fi
}

# --- rust ---------------------------------------------------------------
#
# rustc links the LLVM built above, so the pass reaches Rust code without the
# Rust side knowing anything about it. config.toml is rewritten every time: it
# pins llvm-config and the C/C++ compilers to this tree.
#
# x.py does not notice that an external LLVM changed, so a stale rustc keeps
# emitting the old callback signature and the Rust modules then fail in ways
# that look like kernel bugs. Touching the rustc_llvm shim forces the relink.
build_rust() {
	cat > "$RUST_DIR/config.toml" << EOF
[llvm]
download-ci-llvm = false
[build]
target = ["$RUST_TARGET"]
docs = false
extended = false
[target.$RUST_TARGET]
llvm-config = "$LLVM_BUILD/bin/llvm-config"
cc = "$LLVM_BUILD/bin/clang"
cxx = "$LLVM_BUILD/bin/clang++"
[rust]
codegen-backends = ["llvm"]
debug-assertions = false
channel = "nightly"
EOF
	touch "$RUST_DIR"/compiler/rustc_llvm/build.rs \
	      "$RUST_DIR"/compiler/rustc_llvm/llvm-wrapper/*.cpp 2>/dev/null
	(cd "$RUST_DIR" && python3 x.py build --stage 1 library -j "$JOBS") || return 1

	# Cheap proof that the relink took: the callback the pass declares must
	# have the current five-argument signature, not the old pc-carrying one.
	# Written through a temp dir rather than stdout: rustc does not emit
	# llvm-ir to "-o /dev/stdout" when the input is stdin.
	local probe
	probe=$(mktemp -d /tmp/kcov-df-rustc-probe.XXXXXX) || return 1
	# #[no_mangle]: rustc infers #[inline] for a small pub fn and leaves it to
	# the crates that call it, so the probe would have nothing to instrument.
	echo '#[no_mangle] pub extern "C" fn f(a: u64) -> u64 { a + 1 }' > "$probe/probe.rs"
	"$RUSTC" --crate-type=lib --emit=llvm-ir -O -g \
		-Cpasses=sancov-module \
		-Cllvm-args=-sanitizer-coverage-level=3 \
		-Cllvm-args=-sanitizer-coverage-trace-args \
		--out-dir "$probe" "$probe/probe.rs" >/dev/null 2>&1
	local decl calls
	decl=$(grep -ho 'declare void @__sanitizer_cov_trace_args(.*)' \
		"$probe"/*.ll 2>/dev/null | head -1)
	# The pass declares the callback whenever it runs; only a call shows that
	# -sanitizer-coverage-trace-args itself reached it (a rustc that does not
	# copy -Cllvm-args into the per-context options drops it).
	calls=$(cat "$probe"/*.ll 2>/dev/null |
		grep -c 'call void @__sanitizer_cov_trace_args(')
	rm -rf "$probe"
	if [[ $decl != 'declare void @__sanitizer_cov_trace_args(i32, i32, i64, ptr, i32)' ||
	      ${calls:-0} -eq 0 ]]; then
		say "rust: rustc does not instrument with -Cllvm-args=-sanitizer-coverage-trace-args"
		echo "  want: declare void @__sanitizer_cov_trace_args(i32, i32, i64, ptr, i32), and a call"
		echo "  got:  ${decl:-<no __sanitizer_cov_trace_args declaration at all>}, ${calls:-0} call(s)"
		return 1
	fi
	say "rust: trace_args signature verified: $decl, $calls call(s)"
}

# --- linux --------------------------------------------------------------
#
# The config is built in three steps rather than handed to "vng --build" as a
# list of --configitem: vng reconfigures from its defconfig on every build and
# evaluates the items in one pass, which silently drops any symbol whose
# dependencies are only satisfied later in that pass - CONFIG_RUST among them,
# since RUST_IS_AVAILABLE is computed while the file is parsed. In steps, each
# one is verifiable:
#
#   1. virtme-configkernel seeds a config that can boot under virtme-ng
#      (virtio, 9p, serial console). --no-update keeps an existing one, so a
#      rerun does not throw away what step 2 set.
#   2. scripts/config sets what the tests need, then olddefconfig resolves the
#      dependencies with the right toolchain in the environment.
#   3. the requested symbols are read back. CONFIG_KCOV_DATAFLOW_* carry
#      "depends on !RUST || $(rustc-option,...)", which fails open: a make that
#      cannot see RUSTC probes the default rustc, the dependency goes unmet and
#      every symbol is dropped with no diagnostic. Reading them back is the
#      only way to notice.
#
# CONFIG_WERROR is requested to match CI. Without it the two disagree about
# whether a build warning is fatal -- CONFIG_WERROR defaults to COMPILE_TEST,
# so it is off here and was on in one CI job, which is how a -Wconstant-conversion
# error in lib/base64.c broke one architecture and passed silently on the other.
#
# CONFIG_KCOV_DATAFLOW_NO_INLINE is enabled: it applies -fno-inline only to
# objects that opt into dataflow instrumentation explicitly, which is what the
# test modules do, and never to the whole tree under INSTRUMENT_ALL -- that
# combination does not build, the inliner being load-bearing for inline asm
# "i" operands elsewhere in the kernel.
#
# CONFIG_RUST is only requested when the rebuilt rustc satisfies
# scripts/rust_is_available.sh, so a missing bindgen degrades to a C-only run
# instead of failing the build.
build_linux() {
	local -a want=(
		KCOV KCOV_INSTRUMENT_ALL KCOV_ENABLE_COMPARISONS
		KCOV_DATAFLOW_ARGS KCOV_DATAFLOW_RET KCOV_DATAFLOW_INSTRUMENT_ALL
		KCOV_DATAFLOW_NO_INLINE
		DEBUG_INFO_DWARF5 DEBUG_FS MODULES WERROR
	)
	# Access records (KCOV_DF_ACCESS=0 builds without them, to check that
	# the stream is then what it was before they existed).
	#
	# Off by default with the phase-0-5-a toolchain: it has no
	# -sanitizer-coverage-trace-pointee-access, so the cc-option behind
	# these symbols fails and requesting them would fail the read-back
	# below. KCOV_DF_ACCESS=1 asks for them again with a later toolchain.
	local -a access=(KCOV_DATAFLOW_POINTEE_ACCESS
			 KCOV_DATAFLOW_POINTEE_ACCESS_VOLATILE
			 KCOV_DATAFLOW_POINTEE_ACCESS_ATOMIC)
	if [[ ${KCOV_DF_ACCESS:-0} == 1 ]]; then
		want+=("${access[@]}")
	fi
	local -a make_args=(LLVM=1 CC=clang RUSTC="$RUSTC"
			    RUST_LIB_SRC="$RUST_LIB_SRC")
	local missing=() c

	cd "$LINUX_DIR" || return 1

	virtme-configkernel --defconfig --no-update || return 1

	if make "${make_args[@]}" rustavailable >/dev/null 2>&1; then
		say "linux: requesting CONFIG_RUST=y (rustc accepted)"
		want+=(RUST ANDROID_BINDER_IPC_RUST)
	else
		say "linux: CONFIG_RUST not available; Rust modules will SKIP"
	fi

	# DEBUG_INFO is a choice; selecting DWARF5 is what turns it on. The
	# other members are cleared as well: virtme-configkernel appends
	# DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y, and of two members set the last
	# one in the file wins.
	./scripts/config --disable DEBUG_INFO_NONE --disable DEBUG_INFO_REDUCED \
		--disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --disable DEBUG_INFO_DWARF4
	for c in "${want[@]}"; do
		./scripts/config --enable "$c" || return 1
	done
	if [[ ${KCOV_DF_ACCESS:-0} != 1 ]]; then
		for c in "${access[@]}"; do
			./scripts/config --disable "$c" || return 1
		done
	fi
	# arm64, as in CI: no 32-bit compat (its vdso32 needs the ARM target),
	# and no objects using NEON intrinsics, which the clang of the LLVM base
	# cannot compile in the kernel (22287cb04839 declares the
	# __arm_set_fpm_*scale builtins with uint64_t, which
	# asm/neon-intrinsics.h redefines); see .github/workflows/ci.yml.
	if [[ $LLVM_TARGET == AArch64 ]]; then
		./scripts/config --disable COMPAT --enable EXPERT \
			--disable CRC_OPTIMIZATIONS --disable BTRFS_FS \
			--disable MD_RAID456 --disable ASYNC_XOR --disable XOR_BLOCKS \
			--disable RAID6_PQ --disable CRYPTO_AEGIS128 || return 1
	fi
	make "${make_args[@]}" olddefconfig || return 1

	for c in "${want[@]}"; do
		grep -q "^CONFIG_$c=y\$" .config || missing+=("$c")
	done
	# An int, defaulting to 64, behind the same fail-open rustc-option
	# dependency; the selftests expect pointee snapshots on.
	grep -qE "^CONFIG_KCOV_DATAFLOW_POINTEE_BYTES=[1-9]" .config ||
		missing+=(KCOV_DATAFLOW_POINTEE_BYTES)
	if [[ ${#missing[@]} -gt 0 ]]; then
		say "linux: these did not take: ${missing[*]}"
		return 1
	fi

	make "${make_args[@]}" -j "$JOBS" || return 1
	make "${make_args[@]}" -j "$JOBS" modules || return 1

	# The trace calls' observation descriptors are kept in vmlinux, for
	# "sancov -symbolize-dataflow vmlinux" (see include/asm-generic/vmlinux.lds.h).
	# Disabled for the phase-0-5-a toolchain, which emits no descriptors.
	# "$LLVM_BUILD/bin/llvm-readelf" -S vmlinux | grep -q " __sancov_dataflow " || {
	# 	say "linux: vmlinux has no __sancov_dataflow section"
	# 	return 1
	# }
}

# --- selftest -----------------------------------------------------------

# "headers" first: the C tests include <linux/kcov_dataflow.h>. The install
# target then builds the programs, builds the test modules against this
# configured tree, and drops everything next to a generated run_kselftest.sh.
build_selftest() {
	local args=(LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC")

	make -C "$LINUX_DIR" "${args[@]}" -j "$JOBS" headers || return 1
	make -C "$LINUX_DIR/tools/testing/selftests" TARGETS=kcov_dataflow \
		"${args[@]}" -j "$JOBS" \
		install INSTALL_PATH="$KSELFTEST_DIR" || return 1
	ls -l "$KSELFTEST_DIR/kcov_dataflow"

	# One descriptor section per module -- two fail the load with -EEXIST,
	# see scripts/module.lds.S -- and one sancov can resolve.
	# Disabled for the phase-0-5-a toolchain: no descriptors, and its
	# sancov has no -symbolize-dataflow.
	# local ko n
	# for ko in "$KSELFTEST_DIR"/kcov_dataflow/*.ko; do
	# 	n=$("$LLVM_BUILD/bin/llvm-readelf" -S "$ko" | grep -c " __sancov_dataflow ")
	# 	if [[ $n != 1 ]]; then
	# 		say "selftest: $ko has $n __sancov_dataflow sections, want 1"
	# 		return 1
	# 	fi
	# 	"$LLVM_BUILD/bin/sancov" -symbolize-dataflow "$ko" > /dev/null || return 1
	# done
}

# The banner and the checks below are the local half of
# .github/workflows/ci.yml; see the note at the top of this file.
#
# On matching: a kernel printk can land in the middle of a TAP line, e.g.
# "# ok 2 k[   18.3] workqueue: ... deprecated workqueue". Patterns are
# therefore anchored at the start only, never with a trailing $, so console
# noise cannot turn a passing run into a reported failure.
report_results() {
	local log=$1 rc=0 t m
	local rust=0

	grep -q "^CONFIG_RUST=y" "$LINUX_DIR/.config" 2>/dev/null && rust=1

	echo "============================================"
	echo "  KCOV-DATAFLOW RESULTS: $LABEL"
	echo "============================================"
	grep -E "^(ok|not ok|# (ok|not ok|Totals|FAIL|TIMEOUT|selftests:))|# TIMEOUT" \
		"$log" || echo "MISSING"
	echo "============================================"

	fail() { echo "FAIL: $*"; rc=1; }

	# A killed target reports TIMEOUT and leaves its remaining subtests with
	# no result at all; say so instead of blaming the subtest.
	if grep -qE "# TIMEOUT [0-9]+ seconds" "$log"; then
		echo "--- timed out ---"
		grep -E "# TIMEOUT" "$log"
		fail "a test target exceeded the ${TIMEOUT}s timeout"
	fi

	if [[ ${#MODULE_FILTER[@]} -gt 0 ]]; then
		# -t ran test_modules.py directly: only the named modules have
		# results, so the per-target checks below do not apply.
		for m in "${MODULE_FILTER[@]}"; do
			[[ $m == -t ]] && continue
			grep -qE "^(# )?ok [0-9]+ $m" "$log" ||
				fail "module $m did not report ok"
			if grep -qE "^(# )?ok [0-9]+ $m.*# SKIP" "$log"; then
				fail "module $m was skipped"
			fi
		done
	else
		for t in user_ioctl binderfs_test test_modules.py; do
			grep -qE "^ok [0-9]+ selftests: kcov_dataflow: $t" "$log" ||
				fail "$t did not report ok"
		done

		# Unconditional obj-m, both C: required in every configuration.
		for m in rust_ffi_contract eight_struct_args_c; do
			grep -qE "^# ok [0-9]+ $m" "$log" ||
				fail "module $m did not report ok"
			if grep -qE "^# ok [0-9]+ $m.*# SKIP" "$log"; then
				fail "module $m was skipped"
			fi
		done

		# obj-$(CONFIG_RUST): only required where Rust is enabled.
		if [[ $rust -eq 1 ]]; then
			for m in eight_struct_args_rust rust_kworker_remote; do
				grep -qE "^# ok [0-9]+ $m" "$log" ||
					fail "module $m did not report ok"
				if grep -qE "^# ok [0-9]+ $m.*# SKIP" "$log"; then
					fail "module $m was skipped on a CONFIG_RUST=y build"
				fi
			done
			grep -qE "^# ok [0-9]+ kcov_dataflow.binderfs_setup" "$log" ||
				fail "binderfs did not run on a CONFIG_ANDROID_BINDER_IPC_RUST=y build"
		fi
	fi

	# The DWARF source-map checks need sancov; without it they are skipped,
	# which leaves the mapping of records to source parameters unverified.
	# Disabled for the phase-0-5-a toolchain: its sancov has no
	# -symbolize-dataflow, so test_modules.py skips the DWARF checks.
	# if grep -q "DWARF checks skipped" "$log"; then
	# 	fail "DWARF source map checks did not run (no sancov in the guest)"
	# fi

	if grep -qE "^(# )?not ok" "$log"; then
		echo "--- failing cases ---"
		grep -E "^(# )?not ok" "$log"
		fail "failing test case"
	fi

	if [[ $rc -eq 0 ]]; then
		if [[ $rust -eq 0 ]]; then
			echo "note: CONFIG_RUST unset -- Rust modules and binderfs"
			echo "      are expected to SKIP; this run does not"
			echo "      validate the Rust side."
		fi
		say "All tests passed ($LABEL)"
	fi
	return $rc
}

# The guest runs as root: the tests open /sys/kernel/debug/kcov_dataflow and
# load modules. vmlinux is passed through so test_modules.py can symbolize an
# address with addr2line; module records are matched by kallsyms either way.
run_selftest() {
	local log=${OUTPUT:-$(mktemp /tmp/kcov-df-kselftest.XXXXXX.log)}
	local runner=$KSELFTEST_DIR/run_kselftest.sh
	local cmd

	[[ -x $runner ]] || die "no $runner; the selftest stage builds it"

	if [[ ${#MODULE_FILTER[@]} -gt 0 ]]; then
		cmd="$KSELFTEST_DIR/kcov_dataflow/test_modules.py ${MODULE_FILTER[*]}"
		[[ -f $LINUX_DIR/vmlinux ]] && cmd+=" --vmlinux $LINUX_DIR/vmlinux"
		say "selftest: ${MODULE_FILTER[*]} (log: $log)"
	else
		cmd="$runner -o $TIMEOUT -c kcov_dataflow"
		say "selftest: booting virtme-ng guest, $ACCEL, timeout ${TIMEOUT}s (log: $log)"
	fi

	# test_modules.py checks every record against the module's DWARF source
	# map through sancov; the guest sees the host's file system, so the
	# sancov built with the toolchain is usable as it is.
	[[ -x $LLVM_BUILD/bin/sancov ]] && cmd="env SANCOV=$LLVM_BUILD/bin/sancov $cmd"

	(cd "$LINUX_DIR" && vng --user root --verbose --exec "$cmd") 2>&1 | tee "$log"

	# A clean vng exit is not a pass: KTAP reports per-test status, and a
	# guest that panicked or never reached the runner leaves no ok at all.
	report_results "$log"
}

do_selftest() { build_selftest && run_selftest; }

say "stages: ${STAGES[*]}  ($LABEL, -j $JOBS)"
wants llvm     && run_stage llvm     build_llvm
wants rust     && run_stage rust     build_rust
wants linux    && run_stage linux    build_linux
wants selftest && run_stage selftest do_selftest

if [[ ${#FAILED[@]} -gt 0 ]]; then
	die "failed stages: ${FAILED[*]}"
fi
say "done: ${STAGES[*]}"
