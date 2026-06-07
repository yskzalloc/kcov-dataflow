#!/bin/bash
# Wrapper that adds kcov_dataflow instrumentation to Rust code
# Usage: Set RUSTC=/path/to/rustc-kcov-dataflow.sh in kernel build
#
# Pipeline: rustc → LLVM IR → opt (sancov dataflow) → llc → .o
# Falls through to normal rustc for non-codegen invocations.

REAL_RUSTC="${REAL_RUSTC:-rustc}"
OPT="/home/debian-sid/llvm-project/build/bin/opt"
LLC="/home/debian-sid/llvm-project/build/bin/llc"

# Check if this is a codegen call that produces an object file
if echo "$@" | grep -q "\-\-emit.*obj\|--emit.*link"; then
    # Check if KCOV_DATAFLOW is requested (via env var)
    if [ "${KCOV_DATAFLOW_RUST}" = "1" ]; then
        # Modify: emit LLVM IR instead of object, then post-process
        TMPIR=$(mktemp /tmp/rustc_df_XXXXXX.ll)
        TMPINST=$(mktemp /tmp/rustc_df_XXXXXX_inst.ll)

        # Find the output file
        OUTPUT=""
        ARGS=("$@")
        for i in "${!ARGS[@]}"; do
            if [ "${ARGS[$i]}" = "-o" ]; then
                OUTPUT="${ARGS[$((i+1))]}"
                break
            fi
        done

        # Replace --emit=obj with --emit=llvm-ir and add -g
        MODIFIED_ARGS=$(echo "$@" | sed 's/--emit=[^ ]*/--emit=llvm-ir/g' | sed "s|-o $OUTPUT|-o $TMPIR|g")
        $REAL_RUSTC $MODIFIED_ARGS -g 2>&1

        if [ $? -eq 0 ] && [ -f "$TMPIR" ]; then
            # Run our opt with sancov dataflow
            $OPT -passes='sancov-module' \
                -sanitizer-coverage-level=3 \
                -sanitizer-coverage-trace-args \
                -sanitizer-coverage-trace-ret \
                -S "$TMPIR" -o "$TMPINST" 2>/dev/null

            if [ $? -eq 0 ]; then
                # Compile to object
                $LLC -filetype=obj "$TMPINST" -o "$OUTPUT" 2>/dev/null
                RET=$?
                rm -f "$TMPIR" "$TMPINST"
                exit $RET
            fi
        fi

        # Fallback: normal compilation
        rm -f "$TMPIR" "$TMPINST"
    fi
fi

# Normal rustc invocation
exec $REAL_RUSTC "$@"
