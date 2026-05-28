obj-m := simple_vuln_mod.o

# Just set this — the kernel build system auto-injects
# -fsanitize-coverage=trace-args,trace-ret -g -fno-inline
KCOV_DATAFLOW_simple_vuln_mod.o := y
