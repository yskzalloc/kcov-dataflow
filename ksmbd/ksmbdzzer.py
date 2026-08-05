#!/usr/bin/env python3
"""
ksmbdzzer.py — KSMBD write-side LPE fuzzer.

Usage:
  ksmbdzzer.py init [--install-deps]
  ksmbdzzer.py fuzz -r 5 --grain-max 25                  # whole-fleet, round-based
  ksmbdzzer.py fuzz -r 5 -t write copychunk reparse        # only these grains
  ksmbdzzer.py fuzz -r 5 --kcov                           # mainline KCOV (vs kcov-dataflow)
  ksmbdzzer.py validate -time 10
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import multiprocessing
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent


def _dts():
    """dmesg-style monotonic timestamp `[   SS.uuuuuu]` — same clock base as the
    kernel's printk (CLOCK_MONOTONIC ≈ local_clock, seconds since boot), so a
    fuzzer phase line can be lined up directly against a kernel oops/KASAN line
    in `dmesg`. Prefix log lines with it to correlate host-side fuzzing phases
    with guest-side kernel events."""
    t = time.clock_gettime(time.CLOCK_MONOTONIC)
    sec = int(t)
    return f"[{sec:5d}.{int((t - sec) * 1_000_000):06d}]"


# ─── Colored, located logging (auto-applied to EVERY print in this module) ─────
# Overriding the builtin print (instead of editing ~87 call sites) makes every log
# line uniform: a dmesg-style timestamp (same CLOCK_MONOTONIC base as the kernel,
# so host lines align with a dmesg oops) + the source file:line, wrapped in THIS
# program's 24-bit truecolor so each fuzzer component is visually distinct in a
# combined log. This also retro-fits the timestamp onto lines that were missing it.
# A leading _dts()-style stamp already in the message is stripped so it isn't doubled.
import sys as _sys, os as _os, re as _re, builtins as _bi
_LOG_COLOR = "\033[38;2;107;181;163m"   # #6bb5a3 — ksmbdzzer.py
_LOG_RESET = "\033[0m"
_PINK_BOLD = "\033[1m\033[38;2;255;192;203m"   # #FFC0CB bold — engine banner (which arm is running)
_LOG_TS_RE = _re.compile(r'^\s*\[\s*\d+\.\d{6}\]\s*')   # a pre-existing dmesg stamp
# In-guest liveness heartbeat: EVERY log line stamps this. The in-guest watchdog (below)
# uses it to tell a USERSPACE stall (Python alive, no output) from healthy work — so it
# can unstick a hung wave without the host having to reboot the whole VM.
_LAST_PROGRESS = [time.clock_gettime(time.CLOCK_MONOTONIC)]
def print(*args, **kwargs):
    end = kwargs.pop("end", "\n"); file = kwargs.pop("file", _sys.stdout)
    flush = kwargs.pop("flush", False); sep = kwargs.pop("sep", " ")
    fr = _sys._getframe(1)
    loc = "%s:%d" % (_os.path.basename(fr.f_code.co_filename), fr.f_lineno)
    body = _LOG_TS_RE.sub("", sep.join(str(a) for a in args))
    _LAST_PROGRESS[0] = time.clock_gettime(time.CLOCK_MONOTONIC)
    _bi.print("%s%s %s | %s%s" % (_LOG_COLOR, _dts(), loc, body, _LOG_RESET),
              end=end, file=file, flush=flush)


def _inguest_watchdog(stall_secs):
    """Recover a USERSPACE stall in-guest instead of letting the host reboot the VM.

    If no log line is emitted for `stall_secs` while this thread still runs, the main
    loop is stuck in userspace (a hung grain / blocked wave) — NOT a kernel wedge (a
    real kernel livelock/deadlock would starve this thread too, and only the host
    watchdog can rescue that). We unstick it by SIGKILLing the grain child processes
    the main thread is waiting on, so its wave barrier returns and the round continues.
    The VM stays up, the corpus is not lost, and no reboot/re-do is needed. The host
    watchdog (larger STALL_SECS) stays as the backstop for genuine kernel wedges."""
    while True:
        time.sleep(30)
        idle = time.clock_gettime(time.CLOCK_MONOTONIC) - _LAST_PROGRESS[0]
        if idle < stall_secs:
            continue
        print(f"[!!! IN-GUEST WATCHDOG] no progress for {idle:.0f}s — Python still alive, "
              f"so this is a USERSPACE stall; SIGKILLing stuck grain runs to unblock "
              f"the wave (VM stays up, no reboot).", flush=True)
        try:
            # Match RUNNING libFuzzer grain processes by their unique '-max_total_time'
            # arg — NOT 'grain_', which also matches the P1 `clang ... grain_X.c`
            # compiles (killing those would abort a healthy build; that was the P1 bug).
            subprocess.run(['pkill', '-9', '-f', 'max_total_time'], capture_output=True, timeout=10)
        except Exception as _e:
            print(f"[in-guest watchdog] pkill failed: {_e!r}", flush=True)
        _LAST_PROGRESS[0] = time.clock_gettime(time.CLOCK_MONOTONIC)   # fresh window for recovery


class _HeartbeatStdout:
    """Wrap sys.stdout so ANY output — from THIS module OR grain/gen.py (P1/P2 logging,
    which has its own print override and never touched this module's _LAST_PROGRESS) —
    stamps the heartbeat. Without this the watchdog froze at [P1 START] and killed the
    healthy compiles. Transparent proxy: everything but write() delegates to the real
    stream. gen.py resolves sys.stdout dynamically, so replacing the attribute is enough."""
    def __init__(self, wrapped):
        self._w = wrapped
    def write(self, s):
        _LAST_PROGRESS[0] = time.clock_gettime(time.CLOCK_MONOTONIC)
        return self._w.write(s)
    def __getattr__(self, name):
        return getattr(self._w, name)


def _start_inguest_watchdog():
    """Launch the in-guest watchdog. Threshold from KSMBDZZER_INGUEST_STALL (default
    300s) — keep it BELOW the host STALL_SECS (420s) so a userspace stall is recovered
    in-guest first, and the host reboot only ever fires for a true kernel wedge. 300s
    comfortably clears one P1 compile batch (~130s/batch on the 9p rootfs) between log
    lines so a slow-but-healthy build is never mistaken for a stall."""
    import threading
    try:
        stall = int(_os.environ.get('KSMBDZZER_INGUEST_STALL', '300'))
    except ValueError:
        stall = 300
    if not isinstance(_sys.stdout, _HeartbeatStdout):
        _sys.stdout = _HeartbeatStdout(_sys.stdout)   # heartbeat catches gen.py output too
    _LAST_PROGRESS[0] = time.clock_gettime(time.CLOCK_MONOTONIC)
    threading.Thread(target=_inguest_watchdog, args=(stall,), daemon=True).start()
    return stall


# ─── Configuration (dataclass) ────────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    """Immutable fuzzer configuration."""
    conf_file: Path = field(default_factory=lambda: SCRIPT_DIR / 'ksmbd-sandbox.config')
    corpus_db: Path = Path('/tmp/ksmbdzzer_corpus.json')
    mount: str = '/tmp/ksmbdzzer_mnt'
    share: str = '/tmp/ksmbd_share'
    pwdb: str = '/tmp/ksmbd_conf/ksmbdpwd.db'


CFG = Config()

# Path/name aliases used throughout the module. The kcov_dataflow ioctls, mmap,
# and buffer sizing now live entirely in libksmbdzzer.c (per-worker handle), so
# the old Python-side KCOV_DF_* / BUF_WORDS / libc.mmap constants were removed.
CONF_FILE = CFG.conf_file
CORPUS_DB = CFG.corpus_db
MOUNT = CFG.mount
SHARE = CFG.share
PWDB = CFG.pwdb


# ─── Corpus DB ────────────────────────────────────────────────────────────────

# Host-durable corpus mirror (survives a VM wedge). CORPUS_DB is guest /tmp (fast);
# this copy is on the 9p repo mount so a crash costs the in-flight round, not the run.
_HOST_CORPUS = SCRIPT_DIR / '.fuzzdb' / 'corpus.json'

def corpus_load():
    """Load persistent corpus, giving PRECEDENCE to the previous generation. Prefer the
    hot guest /tmp copy; if it is absent OR corrupt (e.g. truncated by a panic that hit
    mid-write), fall back to the host-durable mirror (.fuzzdb/corpus.json, on the 9p repo
    mount). So a VM wedge/panic costs only the in-flight round — the campaign resumes
    from the last cleanly-saved generation instead of starting cold."""
    for src in (CORPUS_DB, _HOST_CORPUS):
        if not src.exists():
            continue
        try:
            raw = json.loads(src.read_text())
            entries = [(e['offset'], bytes.fromhex(e['data']), e['rank']) for e in raw['corpus']]
            if src is _HOST_CORPUS:
                print(f"  [resume] loaded {len(entries)} corpus entries from the host-durable "
                      f"mirror ({_HOST_CORPUS}) — continuing the previous generation", flush=True)
            return entries, set(raw.get('features', [])), raw.get('value_pool', [])
        except Exception:
            continue                      # corrupt/partial source — try the next one
    return [], set(), []

def _atomic_write_text(path: Path, blob: str):
    """Write blob to path ATOMICALLY (tmp + os.replace). A panic during the write can
    then never leave a truncated/corrupt file — the old copy stays intact until the
    rename flips it in one step. This is what lets the durable corpus survive a crash
    that lands mid-save (the whole point of the host mirror)."""
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(blob)
    os.replace(tmp, path)                 # atomic on the same filesystem

def _ensure_posix_user(name: str, uid: int) -> str:
    """Make `name` getpwnam()-able so ksmbd.mountd can resolve `force user = name`
    in [aclshare] (share.c force_user() drops the share on a getpwnam NULL → the #42
    BAD_NETWORK_NAME). Returns a short status string describing HOW it was provisioned.

    Why not just useradd: under virtme-ng the guest root is the host fs over 9p/
    virtiofs, where shadow-utils' lock (a link()-based /etc/passwd.lock) is
    unsupported, so useradd dies with 'cannot lock /etc/passwd; try again later'
    and never writes the entry. A plain append needs no lock, so fall back to it."""
    def _has(db):
        return subprocess.run(['getent', db, name], capture_output=True).returncode == 0
    if _has('passwd'):
        return 'already present'
    ua = subprocess.run(['useradd', '-M', '-s', '/usr/sbin/nologin', '-u', str(uid), name],
                        capture_output=True, text=True)
    if _has('passwd'):
        return 'useradd'
    # Lock-free fallback: append the entries directly (single writer, init-time only).
    # Works when /etc is 9p/virtiofs (writable, just lock-unfriendly).
    _pw_line = f'{name}:x:{uid}:{uid}:ksmbd fuzz user:/nonexistent:/usr/sbin/nologin\n'
    _gr_line = f'{name}:x:{uid}:\n'
    try:
        if not _has('group'):
            with open('/etc/group', 'a') as f:
                f.write(_gr_line)
        with open('/etc/passwd', 'a') as f:
            f.write(_pw_line)
        if _has('passwd'):
            return f'passwd-append (useradd could not lock: {ua.stderr.strip()[:60]})'
    except OSError:
        pass  # /etc is READ-ONLY (post-rebase VM: ext RO) — fall through to bind-mount.
    # Read-only /etc: bind-mount writable copies of passwd (+group) with `name` appended.
    # A bind mount edits the MOUNT NAMESPACE, not the RO backing fs, so it succeeds where
    # both useradd (needs a lock) and a plain append (needs write perms) fail. The copy
    # preserves every existing entry (root/nobody/…), so nothing else stops resolving.
    import shutil
    try:
        pw_new, gr_new = '/tmp/.ksmbd_etc_passwd', '/tmp/.ksmbd_etc_group'
        shutil.copy('/etc/passwd', pw_new)
        with open(pw_new, 'a') as f:
            f.write(_pw_line)
        subprocess.run(['mount', '--bind', pw_new, '/etc/passwd'], capture_output=True)
        if not _has('group'):
            shutil.copy('/etc/group', gr_new)
            with open(gr_new, 'a') as f:
                f.write(_gr_line)
            subprocess.run(['mount', '--bind', gr_new, '/etc/group'], capture_output=True)
        if _has('passwd'):
            return f'bind-mount (/etc read-only; useradd: {ua.stderr.strip()[:50]})'
    except OSError as e:
        return (f'FAILED — useradd rc={ua.returncode} ({ua.stderr.strip()[:60]}); '
                f'append+bind-mount also failed: {e}')
    return f'FAILED — useradd rc={ua.returncode} ({ua.stderr.strip()[:70]}); append+bind-mount had no effect'

def corpus_save(corpus, features, value_pool):
    """Persist corpus to the hot /tmp DB AND write-through to the host-durable mirror.
    BOTH writes are atomic so a VM panic mid-save cannot corrupt either copy — the
    previous generation's corpus stays intact for the resume."""
    data = {
        'corpus': [{'offset': c[0], 'data': c[1] if isinstance(c[1], str) else c[1].hex(), 'rank': c[2]} for c in corpus[:4096]],
        'features': list(features)[:50000],
        'value_pool': value_pool[:4096],
    }
    blob = json.dumps(data)
    try:
        _atomic_write_text(CORPUS_DB, blob)
    except OSError:
        pass
    try:                                  # write-through to host mount (durability)
        _HOST_CORPUS.parent.mkdir(exist_ok=True)
        _atomic_write_text(_HOST_CORPUS, blob)
    except OSError:
        pass

# ─── Init ─────────────────────────────────────────────────────────────────────

def cmd_init(install_deps=False):
    if install_deps:
        print('[*] Installing dependencies...')
        subprocess.run(['apt-get', 'update', '-qq'], capture_output=True)
        subprocess.run(['apt-get', 'install', '-y', '-qq',
                       'ksmbd-tools', 'cifs-utils', 'smbclient',
                       'krb5-kdc', 'krb5-admin-server',
                       'librdmacm-dev', 'libibverbs-dev', 'rdma-core', 'iproute2'],
                      capture_output=True)
        print('[+] Dependencies installed')

    # Each init step logs START → RESULT so a stall is attributable to a specific
    # step (the mountd start, the CIFS mount retries and the sleeps are the blocking
    # points). Prefix [init]; the print override adds the [time] file:line stamp.
    print('[init] 1/9 creating share/mount directories')
    for d in [SHARE, '/tmp/ksmbd_acl', '/tmp/ksmbd_priv', '/tmp/ksmbd_conf', MOUNT, f'{MOUNT}_acl']:
        os.makedirs(d, exist_ok=True)
    os.chmod(SHARE, 0o777)
    # 0o777 (was 0o755): [aclshare] uses `force user = fuzz`, so ksmbd creates files as
    # fuzz — a root-owned 0o755 backing dir left every write EACCES. POSIX perms here are
    # wide open on purpose; the ACL enforcement under test is the SMB security descriptor
    # path (smbacl.c via the SD grains), not the backing filesystem mode.
    os.chmod('/tmp/ksmbd_acl', 0o777)
    os.chmod('/tmp/ksmbd_priv', 0o777)

    # Load ksmbd module (if not built-in)
    print('[init] 2/9 modprobe ksmbd (no-op if built-in)')
    subprocess.run(['modprobe', 'ksmbd'], capture_output=True)

    # Create user (BOTH a system user and the ksmbd SMB user).
    print('[init] 3/9 provisioning user fuzz (system + SMB)')
    # SYSTEM user first: [aclshare] uses `force user = fuzz`, which ksmbd.mountd resolves
    # via getpwnam() at load — if `fuzz` is not in /etc/passwd, mountd DROPS the share and
    # a tree-connect returns BAD_NETWORK_NAME (the #42 aclshare failure). ksmbd.adduser only
    # populates the ksmbd SMB user DB, not /etc/passwd, so create the POSIX user too.
    # uid is fixed (not auto) so ownership is stable across resumes.
    _prov = _ensure_posix_user('fuzz', 4242)
    if _prov.startswith('FAILED'):
        # Ground-truth WHY the lock-free append could not help: fs type of /etc (9p/
        # virtiofs/overlay) + any stale shadow lock files left by a killed useradd.
        _fs = subprocess.run(['stat', '-f', '-c', '%T', '/etc'], capture_output=True, text=True).stdout.strip()
        _locks = subprocess.run('ls -1 /etc/passwd.lock /etc/.pwd.lock /etc/shadow.lock /etc/group.lock',
                                shell=True, capture_output=True, text=True).stdout.split()
        print(f'[init]     !!! system user fuzz {_prov} — aclshare will be dropped '
              f'[/etc fs={_fs or "?"}; stale locks={_locks or "none"}]')
    else:
        _pw = subprocess.run(['getent', 'passwd', 'fuzz'], capture_output=True, text=True)
        print(f'[init]     system user OK via {_prov}: {_pw.stdout.strip()}')
    subprocess.run(f'ksmbd.adduser -C {CONF_FILE} -P {PWDB} -a fuzz -p fuzz'.split(), capture_output=True)

    # RDMA setup (before ksmbd.mountd so listener binds to IB device)
    print('[init] 4/9 setting up Software RDMA transport (SIW/RXE)')
    try:
        _setup_target_transport()
    except Exception as e:
        print(f'[init]     RDMA setup skipped: {e!r}')
    time.sleep(1)

    # Kill any existing mountd, then start fresh
    print('[init] 5/9 (re)starting ksmbd.mountd user daemon')
    subprocess.run(['pkill', '-9', 'ksmbd.mountd'], capture_output=True)
    time.sleep(0.5)
    # Capture mountd's VERBOSE load log (was DEVNULL → we were blind to WHY a share is
    # dropped). ksmbd.mountd -v logs each share it parses/exports and any per-share error
    # (bad path, unresolvable force user, …). We tail it on an aclshare mount failure.
    _MOUNTD_LOG = '/tmp/ksmbd_mountd.log'
    _mf = open(_MOUNTD_LOG, 'w')
    subprocess.Popen(f'ksmbd.mountd -C {CONF_FILE} -P {PWDB} -n -v'.split(),
                     stdout=_mf, stderr=_mf)
    time.sleep(2)
    print('[init]     ksmbd.mountd started (waited 2s for listener)')

    # Mount CIFS share (try 3.1.1, fallback to 3.0)
    print('[init] 6/9 mounting //127.0.0.1/share (dialect 3.1.1→3.0→2.1)')
    # Turn on ksmbd's session-setup/auth diagnostics ONLY around the mount so a rejection
    # prints its EXACT reason ("Unexpected OID", "authentication failed", a krb5/IPC error)
    # instead of just STATUS_INVALID_PARAMETER — then silence it before the fuzz run, which
    # would otherwise flood dmesg with millions of ops. TWO independent switches:
    #  (1) ksmbd_debug() is gated by the ksmbd_debug_types BITMASK (glob.h), NOT dynamic-debug
    #      — toggle it via the ksmbd-control class attr ('all' flips 0↔KSMBD_DEBUG_ALL; a fresh
    #      boot starts at 0, so one write enables, a second disables).
    #  (2) generic pr_debug() in the VFS/RDMA ksmbd calls into uses real dynamic-debug.
    def _ksmbd_debug(on):
        try:
            with open('/sys/class/ksmbd-control/debug', 'w') as _d:
                _d.write('all')            # toggle: 0→ALL to enable, ALL→0 to disable
        except OSError as _e:
            if on:
                print(f'[init]     (ksmbd_debug bitmask not enabled: {_e})')
    try:
        with open('/sys/kernel/debug/dynamic_debug/control', 'w') as _dd:
            _dd.write('file fs/smb/server/* +p')
    except OSError as _e:
        print(f'[init]     (dynamic-debug not enabled: {_e})')
    _ksmbd_debug(True)
    mounted = False
    for vers in ['3.1.1', '3.0', '2.1']:
        print(f'[init]     mount attempt vers={vers} ...')
        r = subprocess.run(
            f'mount -t cifs //127.0.0.1/share {MOUNT} -o username=fuzz,password=fuzz,vers={vers},cache=none,noperm'.split(),
            capture_output=True)
        if r.returncode == 0:
            mounted = True
            print(f'[init]     mounted share at {MOUNT} (vers={vers})')
            break
        print(f'[init]     vers={vers} failed rc={r.returncode}: {r.stderr.decode().strip()[:120]}')
    if not mounted:
        print(f'[-] CIFS mount failed (all dialects): {r.stderr.decode().strip()}')
        # Dump the ksmbd kernel-side reason (dynamic-debug enabled above) — the ground
        # truth for WHY session setup was rejected, so we don't guess from the status code.
        try:
            _dk = subprocess.run(['dmesg'], capture_output=True, text=True)
            _kl = [l for l in _dk.stdout.splitlines()
                   if any(k in l for k in ('ksmbd', 'smb2', 'ntlm', 'OID', 'auth', 'spnego', 'IPC'))]
            if _kl:
                print('[init]     ksmbd kernel log (session-setup cause):')
                for l in _kl[-14:]:
                    print(f'[init]       {l}')
        except OSError as _de:
            print(f'[init]     (dmesg dump failed: {_de!r})')
        return
    # Mount OK — silence ksmbd's SMB/AUTH debug so the fuzz run doesn't flood dmesg with
    # per-op logging (millions of ops). The pr_err() paths still print if something breaks.
    _ksmbd_debug(False)

    # Write test file
    try:
        Path(f'{MOUNT}/fuzz_target').write_bytes(b'x')
        print('[init] 7/9 wrote fuzz_target probe file (share is writable)')
    except OSError as e:
        print(f'[-] Write test failed: {e}')
        return

    # ACL share (optional — known gap #42 if it fails with BAD_NETWORK_NAME)
    r2 = subprocess.run(
        f'mount -t cifs //127.0.0.1/aclshare {MOUNT}_acl -o username=fuzz,password=fuzz,vers=3.0,cache=none'.split(),
        capture_output=True)
    if r2.returncode == 0:
        print('[init] 8/9 aclshare mounted (ACL grain live)')
        try:
            Path(f'{MOUNT}_acl/fuzz_acl').write_bytes(b'x')
        except OSError:
            pass
    else:
        print(f'[init] 8/9 aclshare NOT mounted rc={r2.returncode} (optional; ACL grain dead — #42): '
              f'{r2.stderr.decode().strip()[:100]}')
        # Dump WHY mountd dropped the share (ground truth instead of guessing): the mountd
        # verbose log lines that mention aclshare / fuzz / the share path.
        try:
            _ml = Path(_MOUNTD_LOG).read_text().splitlines()
            _hits = [l.strip() for l in _ml
                     if any(k in l.lower() for k in ('aclshare', 'ksmbd_acl', 'force user', 'fuzz', 'share'))]
            if _hits:
                print('[init]     mountd log (aclshare cause): ' + ' ┃ '.join(_hits[-8:]))
            else:
                print(f'[init]     mountd log had no aclshare line; full tail: '
                      + ' ┃ '.join(l.strip() for l in _ml[-6:]))
            # also confirm the backing path actually exists as mountd sees it
            _p = Path('/tmp/ksmbd_acl')
            print(f'[init]     path /tmp/ksmbd_acl exists={_p.is_dir()} '
                  f'mode={oct(_p.stat().st_mode & 0o777) if _p.exists() else "-"}')
        except Exception as _de:
            print(f'[init]     (mountd-log diag failed: {_de!r})')

    # NDR/IPC$ exercise (optional — tests srvsvc)
    try:
        subprocess.run(
            'smbclient //127.0.0.1/ipc$ -U fuzz%fuzz -c help -m SMB3'.split(),
            capture_output=True, timeout=5)
        print('[init] 9/9 NDR/IPC$ exercised (srvsvc reachable)')
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f'[init] 9/9 IPC$ probe skipped ({type(e).__name__})')

    # KDC setup (optional — for Kerberos fuzzing)
    print('[init]     setting up KDC (optional, Kerberos auth path)')
    _setup_target_auth()

    print(f'[+] KSMBD ready: {MOUNT}')


def _setup_target_auth():
    """Set up minimal KDC for Kerberos auth path fuzzing. Non-fatal if fails."""
    try:
        kdc_dir = Path('/tmp/kdc')
        kdc_dir.mkdir(exist_ok=True)
        krb5_conf = Path('/tmp/krb5.conf')
        kdc_conf = kdc_dir / 'kdc.conf'
        krb5_conf.write_text(
            '[libdefaults]\n'
            '  default_realm = FUZZ.LOCAL\n'
            '  dns_lookup_realm = false\n'
            '  dns_lookup_kdc = false\n'
            '[realms]\n'
            '  FUZZ.LOCAL = {\n'
            '    kdc = 127.0.0.1\n'
            '    admin_server = 127.0.0.1\n'
            '  }\n'
            '[domain_realm]\n'
            '  .fuzz.local = FUZZ.LOCAL\n')
        kdc_conf.write_text(
            '[kdcdefaults]\n'
            '  kdc_listen = 88\n'
            '[realms]\n'
            '  FUZZ.LOCAL = {\n'
            '    database_name = /tmp/kdc/principal\n'
            '    key_stash_file = /tmp/kdc/.k5.FUZZ.LOCAL\n'
            '    max_life = 10h\n'
            '    max_renewable_life = 7d\n'
            '  }\n')
        env = {**os.environ, 'KRB5_CONFIG': str(krb5_conf), 'KRB5_KDC_PROFILE': str(kdc_conf)}
        os.environ['KRB5_CONFIG'] = str(krb5_conf)
        os.environ['KRB5_KDC_PROFILE'] = str(kdc_conf)
        if not (kdc_dir / 'principal').exists():
            subprocess.run('kdb5_util create -s -r FUZZ.LOCAL -P fuzzpass'.split(),
                          capture_output=True, timeout=10, env=env)
            for princ in ['fuzz', 'cifs/127.0.0.1']:
                subprocess.run(
                    f'kadmin.local -q addprinc -pw fuzz {princ}@FUZZ.LOCAL'.split(),
                    capture_output=True, timeout=5, env=env)
        subprocess.Popen(['krb5kdc', '-n'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        time.sleep(0.5)
        print('[+] KDC running (FUZZ.LOCAL, port 88)')
    except Exception:
        print('[+] KDC not available (optional)')

    # PC normalization
    _get_target_text_base()
    if _target_text_base:
        print(f'[+] ksmbd .text base: 0x{_target_text_base:x}')


def _setup_target_transport():
    """Initialize Software RDMA for SMBDirect fuzzing.

    SIW (iWARP) on eth0 with bridge networking = proven working path.
    RXE on lo = fallback (address resolution issues with RDMA CM).
    Kernel has CONFIG_RDMA_RXE=y CONFIG_RDMA_SIW=y (built-in, no modprobe).
    """
    print('[*] Setting up Software RDMA...')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], capture_output=True)

    # Find non-lo interface
    r = subprocess.run(['ip', '-o', 'link', 'show', 'up'], capture_output=True, text=True)
    iface = None
    for line in r.stdout.splitlines():
        if 'lo' not in line and 'LOOPBACK' not in line:
            parts = line.split(':')
            if len(parts) >= 2:
                iface = parts[1].strip(); break

    # Primary: SIW on real interface (requires --network bridge)
    if iface:
        r2 = subprocess.run(['ip', '-4', 'addr', 'show', iface], capture_output=True, text=True)
        if 'inet ' not in r2.stdout:
            subprocess.run(['ip', 'addr', 'add', '192.168.122.50/24', 'dev', iface], capture_output=True)
            subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True)
        subprocess.run(['rdma', 'link', 'del', 'siw0'], capture_output=True)
        r = subprocess.run(['rdma', 'link', 'add', 'siw0', 'type', 'siw', 'netdev', iface],
                          capture_output=True, text=True)
        if r.returncode == 0:
            print(f'[+] RDMA link siw0 (SIW/iWARP) on {iface}')
            return

    # Fallback: RXE on dummy interface (RDMA CM needs a real IP, not loopback)
    subprocess.run(['ip', 'link', 'add', 'dummy0', 'type', 'dummy'], capture_output=True)
    subprocess.run(['ip', 'addr', 'add', '10.0.99.1/24', 'dev', 'dummy0'], capture_output=True)
    subprocess.run(['ip', 'link', 'set', 'dummy0', 'up'], capture_output=True)
    subprocess.run(['rdma', 'link', 'del', 'rxe0'], capture_output=True)
    r = subprocess.run(['rdma', 'link', 'add', 'rxe0', 'type', 'rxe', 'netdev', 'dummy0'],
                      capture_output=True, text=True)
    if r.returncode == 0:
        print('[+] RDMA link rxe0 (Soft-RoCE) on dummy0 (10.0.99.1)')
    else:
        print('[-] RDMA setup failed')


# ─── Persistent Mode + PC Normalization ──────────────────────────────────────

_target_text_base = 0

def _get_target_text_base():
    """Read ksmbd module .text base for PC normalization."""
    global _target_text_base
    try:
        with open('/sys/module/ksmbd/sections/.text') as f:
            _target_text_base = int(f.read().strip(), 16)
    except (FileNotFoundError, ValueError, PermissionError):
        _target_text_base = 0
    return _target_text_base


# ─── Dataflow records + access-control contract model ─────────────────────────
# Mirrors `struct pfz_rec` in libksmbdzzer.c — keep field order in sync.
class DataflowRec(ctypes.Structure):
    _fields_ = [
        ("pc",      ctypes.c_uint64),
        ("vals",    ctypes.c_uint64 * 6),
        ("type",    ctypes.c_uint32),   # 0xE entry, 0xF return
        ("arg_idx", ctypes.c_uint32),
        ("size",    ctypes.c_uint32),
        ("nfields", ctypes.c_uint32),
        ("seq",     ctypes.c_uint32),
        ("_pad",    ctypes.c_uint32),
    ]

# SMB2 DesiredAccess bits / dispositions / create options (fs/smb/common/smb2pdu.h)
FILE_READ_DATA        = 0x00000001
FILE_WRITE_DATA       = 0x00000002
FILE_APPEND_DATA      = 0x00000004
FILE_READ_EA          = 0x00000008
FILE_WRITE_EA         = 0x00000010
FILE_READ_ATTRIBUTES  = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_DELETE           = 0x00010000
FILE_GENERIC_WRITE    = 0x40000000
FILE_GENERIC_READ     = 0x80000000
# FILE_WRITE_DESIRE_ACCESS_LE — the mask smb2_create_open_flags() treats as "write"
WRITE_DESIRE_MASK = (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                     FILE_WRITE_ATTRIBUTES | FILE_GENERIC_WRITE)

FILE_DIRECTORY_FILE    = 0x00000001
FILE_NON_DIRECTORY_FILE= 0x00000040
FILE_DELETE_ON_CLOSE   = 0x00001000
# CreateDisposition & FILE_CREATE_MASK (0x7); these set O_TRUNC when file present
DISP_SUPERSEDE, DISP_OPEN, DISP_CREATE = 0, 1, 2
DISP_OPEN_IF, DISP_OVERWRITE, DISP_OVERWRITE_IF = 3, 4, 5
TRUNC_DISPOSITIONS = {DISP_SUPERSEDE, DISP_OVERWRITE, DISP_OVERWRITE_IF}

# Host-visible: SCRIPT_DIR (ksmbd/) is 9p-mapped from the host under virtme,
# whereas the VM's /tmp is an ephemeral tmpfs overlay. Reproducers must survive
# VM exit, so write them next to the fuzzer. Override with KSMBDZZER_FINDINGS.
FINDINGS_DIR = Path(os.environ.get("KSMBDZZER_FINDINGS", str(SCRIPT_DIR / "findings")))

# ─── Durable arbiter DB (host-mount, survives a VM wedge) ─────────────────────
# The distilled cross-round feedback (g_fb) lives on the repo mount, NOT guest
# /tmp — so a VM crash costs the in-flight round, not the campaign's learning.
FUZZDB = SCRIPT_DIR / '.fuzzdb'
try:
    FUZZDB.mkdir(exist_ok=True)
except OSError:
    pass

def write_feedback(hot_offs, vals):
    """Pack the arbiter feedback (g_fb) for the C connector. Layout MUST stay in
    sync with `struct feedback` in grain/common.h:
      <I magic=0xF00DDA7A, I n_hot, I n_val, I pad, 64H hot_off, 128Q vals>.
    Written to FUZZDB/fb.bin; grains read it via load_feedback()/$GRAIN_FB."""
    hot = list(dict.fromkeys(int(o) & 0xFFFF for o in hot_offs if 0 <= int(o) < 4096))[:64]
    vv = list(dict.fromkeys(int(v) & 0xFFFFFFFFFFFFFFFF for v in vals if int(v)))[:128]
    blob = struct.pack('<IIII', 0xF00DDA7A, len(hot), len(vv), 0)
    blob += struct.pack('<64H', *(hot + [0] * (64 - len(hot))))
    blob += struct.pack('<128Q', *(vv + [0] * (128 - len(vv))))
    try:
        (FUZZDB / 'fb.bin').write_bytes(blob)
        return len(hot), len(vv)
    except OSError:
        return 0, 0


def vlog(msg):
    """Verbose trace (only when --verbose / KSMBDZZER_VERBOSE=1). Propagated via
    env so it survives fork into ProcessPoolExecutor workers."""
    if os.environ.get("KSMBDZZER_VERBOSE") == "1":
        print(f"  [v] {msg}", flush=True)


def verbose_on() -> bool:
    return os.environ.get("KSMBDZZER_VERBOSE") == "1"


def corpus_bug_id(*chunks) -> str:
    """BLAKE2b identity for a bug-triggering corpus entry. Hashes the exact
    bytes that produced the bug (PDU/body/input) so every distinct trigger has
    a stable, collision-resistant id for dedup and cross-referencing."""
    h = hashlib.blake2b(digest_size=16)
    for c in chunks:
        if c is None:
            continue
        if isinstance(c, str):
            c = c.encode()
        elif not isinstance(c, (bytes, bytearray)):
            c = str(c).encode()
        h.update(bytes(c))
        h.update(b"\x1e")  # record separator so concatenations don't alias
    return h.hexdigest()

# Persistent library handle (survives across rounds — accumulates state)
_persistent_lib = None

# Per-worker coverage identity. Each pool worker dials 127.0.0.<octet> and the
# kernel routes that connection's kcov-dataflow into the worker's private
# buffer (see KSMBD_KCOV_IP_HANDLE in fs/smb/server/connection.h). The
# parent / sequential path keeps octet 1 (127.0.0.1); pool workers get 2,3,...
_WORKER_OCTET = 1

def _pool_init(counter):
    """ProcessPoolExecutor initializer: hand each worker a unique octet."""
    global _WORKER_OCTET, _persistent_lib
    # Workers ignore Ctrl+C so a single interrupt propagates cleanly to the parent
    # (default handler) instead of every worker raising its own KeyboardInterrupt
    # and racing a storm of tracebacks over the corpus save.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    with counter.get_lock():
        counter.value += 1
        _WORKER_OCTET = counter.value  # 2, 3, 4, ... (parent stays 1)
    # With the fork start method a worker inherits the parent's already-built
    # _persistent_lib (octet 1). Drop it so the next _get_lib() re-initializes
    # with THIS worker's octet and registers its own private coverage handle.
    _persistent_lib = None

def _get_lib(init=True):
    """Get or create the persistent libksmbdzzer handle.

    init=True (default): also run pfz_init() — open the coverage handle + SMB session.
    init=False: registry-only (pfz_grain_count/pfz_grain_name). build-grains uses this —
    it only COMPILES grains on the host and needs neither coverage nor a live ksmbd, so it
    must not trigger the spurious open(kcov)/connection-refused churn there."""
    global _persistent_lib
    if _persistent_lib is None:
        _persistent_lib = ctypes.CDLL(str(SCRIPT_DIR / 'libksmbdzzer.so'))
        _persistent_lib.pfz_write.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_write.restype = ctypes.c_int
        _persistent_lib.pfz_truncate.argtypes = [ctypes.c_long]
        _persistent_lib.pfz_raw_pdu.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_raw_pdu.restype = ctypes.c_int
        _persistent_lib.pfz_get_features.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_int]
        _persistent_lib.pfz_get_features.restype = ctypes.c_int
        _persistent_lib.pfz_race_write_close.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        _persistent_lib.pfz_compress_fuzz.argtypes = [ctypes.c_uint16, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
        _persistent_lib.pfz_pool_init_authed.restype = ctypes.c_int
        _persistent_lib.pfz_pool_oplock_race.argtypes = [ctypes.c_char_p]
        _persistent_lib.pfz_pool_lock_race.argtypes = [ctypes.c_int]
        _persistent_lib.pfz_pool_race_authed.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_session_binding_race.restype = ctypes.c_int
        _persistent_lib.pfz_durable_reconnect.argtypes = [ctypes.c_char_p]
        _persistent_lib.pfz_ndr_fuzz.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_query_dir.argtypes = [ctypes.c_uint8, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_copychunk.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_int]
        _persistent_lib.pfz_compound.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_raw_pdu_authed.argtypes = [ctypes.c_uint16, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_pool_init.argtypes = [ctypes.c_int]
        _persistent_lib.pfz_set_failslab.argtypes = [ctypes.c_int]
        _persistent_lib.pfz_negotiate_contexts.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_unknown_pipe.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_unicode_path.argtypes = [ctypes.c_char_p, ctypes.c_int]
        # Grain registry (new phase architecture): enumerate + run normal-scenario grains
        _persistent_lib.pfz_grain_count.restype = ctypes.c_int
        _persistent_lib.pfz_grain_name.argtypes = [ctypes.c_int]
        _persistent_lib.pfz_grain_name.restype = ctypes.c_char_p
        _persistent_lib.pfz_grain_run.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_grain_run.restype = ctypes.c_int
        _persistent_lib.pfz_grain_combo2.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_grain_combo2.restype = ctypes.c_int
        # Dataflow records + authenticated probe (I2S mutator + contract oracle)
        _persistent_lib.pfz_get_records.argtypes = [ctypes.POINTER(DataflowRec), ctypes.c_int]
        _persistent_lib.pfz_get_records.restype = ctypes.c_int
        _persistent_lib.pfz_get_pc_ret_pairs.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_int]
        _persistent_lib.pfz_get_pc_ret_pairs.restype = ctypes.c_int
        _persistent_lib.pfz_probe_init_share.argtypes = [ctypes.c_char_p]
        _persistent_lib.pfz_probe_send.argtypes = [ctypes.c_uint16, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _persistent_lib.pfz_probe_send.restype = ctypes.c_int
        _persistent_lib.pfz_probe_reconnect.argtypes = [ctypes.c_char_p]
        _persistent_lib.pfz_probe_reconnect.restype = ctypes.c_int
        _persistent_lib.pfz_probe_send_frag.argtypes = [ctypes.c_uint16, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        _persistent_lib.pfz_probe_send_frag.restype = ctypes.c_int
        _persistent_lib.pfz_probe_get_fid.argtypes = [ctypes.c_char_p]
        if init:
            if _persistent_lib.pfz_init(_WORKER_OCTET) < 0:
                print(f"  [!] libksmbdzzer init failed (octet {_WORKER_OCTET}), reconnecting...", flush=True)
                _persistent_lib.pfz_reconnect()
        _persistent_lib._initialized = init
    return _persistent_lib


# ─── Target-function resolver (PC → ksmbd function via /proc/kallsyms) ─────────
class TargetMap:
    """Resolve [start,end) address ranges for the ksmbd write/parse call graph so
    dataflow records can be attributed to a specific function. Degrades to an
    empty map (oracle still works from input+status) if kallsyms is restricted.

    Upgrade 2: the allowlist was 5 symbols, so all but two functions' dataflow
    records were anonymous value-counters. Widen it to the write-side + request-
    parse graph — CREATE/WRITE/READ/SET_INFO/IOCTL/rename/xattr/lock/lease/oplock/
    copychunk — so i2s_correspondence() can label (and the oracle can key on) far
    more of the arguments the kernel actually reports.
    Upgrade 4: make resolution robust — drop kptr_restrict if it hides addresses,
    and count how many targets actually resolved so 'anonymous' is visible, not
    silent."""
    TARGETS = (
        # CREATE / open gate
        "smb2_open", "smb2_create", "smb2_create_open_flags", "smb2_creat",
        # WRITE / READ
        "smb2_write", "ksmbd_vfs_write", "smb2_read", "ksmbd_vfs_read",
        # truncate / set-info (size, disposition, rename via SET_INFO)
        "ksmbd_vfs_truncate", "smb2_set_info_file", "set_file_allocation_info",
        "set_end_of_file_info", "set_rename_info", "set_file_disposition_info",
        # delete / rename / link / mkdir
        "ksmbd_vfs_remove_file", "ksmbd_vfs_unlink", "ksmbd_vfs_rename",
        "ksmbd_vfs_link", "ksmbd_vfs_mkdir", "ksmbd_vfs_fp_rename",
        # xattr / streams / ACL
        "ksmbd_vfs_setxattr", "ksmbd_vfs_getxattr", "ksmbd_vfs_remove_xattr",
        "ksmbd_vfs_set_dos_attrib_xattr", "smb2_set_ea",
        # lock / lease / oplock
        "smb2_lock", "smb2_lease_break", "smb_grant_oplock", "find_same_lease_key",
        "smb2_oplock_break", "ksmbd_vfs_lock",
        # ioctl / copychunk / fsctl
        "smb2_ioctl", "fsctl_copychunk", "ksmbd_vfs_copy_file_ranges",
        # query
        "smb2_query_dir", "smb2_query_info", "ksmbd_vfs_getattr",
        # request-parse / bounds gate (where length/offset bugs are validated)
        "ksmbd_smb2_check_message", "smb2_get_data_area_len",
        "smb2_calc_size", "ksmbd_smb_request",
    )

    def __init__(self):
        self.ranges = {}
        self.resolved = 0
        self._load()
        # Upgrade 4: if kallsyms handed us all-zero / no addresses, kptr_restrict is
        # likely on. Try to drop it (root in the guest) and re-read once.
        if not self.ranges:
            try:
                with open("/proc/sys/kernel/kptr_restrict", "w") as f:
                    f.write("0\n")
                self._load()
            except OSError:
                pass

    def _load(self):
        try:
            syms = []
            with open("/proc/kallsyms") as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 3 and p[1] in "tT":
                        a = int(p[0], 16)
                        if a:
                            syms.append((a, p[2]))
            syms.sort()
            want = set(self.TARGETS)
            ranges = {}
            for i, (a, n) in enumerate(syms):
                if n in want and n not in ranges:
                    end = syms[i + 1][0] if i + 1 < len(syms) else a + 0x2000
                    ranges[n] = (a, end)
            self.ranges = ranges
            self.resolved = len(ranges)
        except Exception:
            self.ranges = {}
            self.resolved = 0

    def whatis(self, pc):
        for name, (s, e) in self.ranges.items():
            if s <= pc < e:
                return name
        return None


# ─── Data-flow-guided I2S steering primitives (RedQueen + GREYONE + AFLGo-lite) ─
# The methodology, stated in CS terms: use the kcov-dataflow VALUE observation as
# the input-to-state channel (RedQueen), drive controlled fields to edges, and reward
# inputs by symbol-address distance to a target (directed greybox, AFLGo-lite). No
# disassembly reasoning, no SMT, no LLM — the kernel tells us the value, we just find
# it in the input and steer it.

# Boundary/target values per width — where length/offset/flag bugs live.
_I2S_BOUNDARIES = {
    2: (0x0000, 0x0001, 0x7fff, 0x8000, 0xffff),
    4: (0x00000000, 0x00000001, 0x7fffffff, 0x80000000, 0xffffffff),
    8: (0, 1, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff),
}


def i2s_correspondence(body, recs, tmap=None):
    """RedQueen input-to-state map. For each observed kernel ENTRY-arg value, locate
    its little-endian encoding in `body`. Returns {offset: (value, width, func,
    arg_idx)} — literal proof that input bytes [offset:offset+width] control a kernel
    argument. This is the core of the data-flow-guided I2S methodology: the kernel
    reported the value via kcov-dataflow; we just find it in the input (no SMT, no
    disassembly). Works because SMB2 fields (access/disposition/options/offset/length)
    are DIRECT, untransformed — exactly the input-to-state correspondence hypothesis."""
    corr = {}
    for r in recs:
        if r.type != 0xE:                     # entry args only
            continue
        func = tmap.whatis(r.pc) if tmap else None
        for i in range(min(r.nfields, 6)):
            v = int(r.vals[i])
            if v == 0 or v >= (1 << 64):
                continue
            for width in (8, 4, 2):
                if v >> (width * 8):
                    continue
                off = body.find(v.to_bytes(width, "little"))
                if off >= 0:
                    corr[off] = (v, width, func, int(r.arg_idx))
                    break
    return corr


# ─── I2S directed mutator + access-control contract oracle ────────────────────
_emitted_findings = set()   # dedup reproducers across cycles/workers

class DataflowDirector:
    """Always-on write-side LPE hunt:
      1. I2S mutator — builds CREATE/WRITE bodies whose le-encoded fields land
         as smb2_create_open_flags()/ksmbd_vfs_write() arguments, steering them
         to the dangerous access/disposition/option combinations.
      2. Contract oracle — over the dataflow record stream, flags a privileged
         create/truncate/delete reached with insufficient granted access and
         emits a record-level reproducer (input bytes + observed args + status).

    ARBITER (DONE): _distill() closes the cross-round data-driven loop — from this
    director's trace-args/ret records + oracle interest it computes {hot offsets,
    interesting values}, packs them (write_feedback) to FUZZDB/fb.bin, and the C
    mutate_i2s() reads them at init. Behavior changes via DATA (corpus + g_fb + live
    df_buf), C frozen (compile once). Only fires when the director authenticates —
    so it is currently gated behind the open AUTH bug.
    TODO(next-step): keep a fraction of the fleet on plain havoc as a CONTROL so a
    bad g_fb can't blind the whole fleet and directed-vs-havoc stays comparable.
    """
    _tmap = None

    def __init__(self, lib, worker_octet=1):
        self.lib = lib
        self.octet = worker_octet
        if DataflowDirector._tmap is None:
            DataflowDirector._tmap = TargetMap()
        self.tmap = DataflowDirector._tmap
        self._recbuf = (DataflowRec * 4096)()
        self._resp = ctypes.create_string_buffer(8192)
        self._retbuf = (ctypes.c_uint64 * 4096)()   # RedQueen return harvest (upgrade 3)
        self._ret_acc = set()
        self.ready = False

    # ---- transport helpers ----------------------------------------------------
    def _probe(self, cmd, body):
        r = self.lib.pfz_probe_send(cmd, body, len(body), self._resp, 8192)
        if r < 12:
            return None, -1
        # Harvest this request's kernel RETURN values BEFORE the next send resets
        # the dataflow buffer (upgrade 3 — RedQueen returned-value → future token).
        self._accumulate_returns()
        status = int.from_bytes(self._resp.raw[8:12], "little")
        return self._resp.raw[:r], status

    def _accumulate_returns(self):
        """Pull the (pc, ret_value) pairs the kernel just produced (0xF records) and
        keep the plausibly-useful magic constants. A size/handle/error the kernel
        COMPUTED and returned is exactly what a downstream comparison will check the
        NEXT input against — so feeding it back as a dictionary token lets the mutator
        satisfy that check without brute force. Skips 0/1 (trivial) and kernel
        pointers (0xffff… — not splice-able into a wire field)."""
        try:
            got = self.lib.pfz_get_pc_ret_pairs(self._retbuf, 2048)
        except Exception:
            return
        for i in range(got):
            v = int(self._retbuf[i * 2 + 1]) & 0xFFFFFFFFFFFFFFFF
            if v <= 1 or v >= 0xffff000000000000:
                continue
            self._ret_acc.add(v)
            if len(self._ret_acc) > 4096:            # bound the working set
                return

    def _flush_return_tokens(self):
        """Write the harvested return values into the shared live dict every grain
        in subsequent waves reads (`-dict=/tmp/ksmbdzzer_live.dict`). Each value is
        emitted little-endian in whatever width holds it — the encoding it appears in
        on the SMB2 wire — so libFuzzer can splice it directly into a field."""
        if not self._ret_acc:
            return
        live = Path('/tmp/ksmbdzzer_live.dict')
        try:
            existing = set(live.read_text().splitlines()) if live.exists() else set()
        except OSError:
            existing = set()
        lines = list(existing)
        added = 0
        for v in sorted(self._ret_acc):
            width = 4 if not (v >> 32) else 8
            esc = "".join("\\x%02x" % c for c in v.to_bytes(width, "little"))
            entry = 'ret_%d_%x="%s"' % (width, v, esc)
            if entry not in existing:
                lines.append(entry); existing.add(entry); added += 1
        if added:
            if len(lines) > 2000:                    # libFuzzer dislikes huge dicts
                lines = lines[-2000:]
            try:
                live.write_text("\n".join(lines) + "\n")
                print(f"  [redqueen] harvested {added} kernel return value(s) → live "
                      f"dict ({len(lines)} tokens carried to next wave)", flush=True)
            except OSError:
                pass

    def _distill(self):
        """ARBITER: distill this director's dataflow records + oracle interest into
        the g_fb the C mutate_i2s() reads next round — closing the cross-round
        data-driven loop (compile once, behavior from data). Writes FUZZDB/fb.bin.

        hot offsets = the write-side CREATE/WRITE fields + any body offset the I2S
        map tied to a kernel argument. values = the dangerous access/disp/option
        combos the oracle cares about + boundaries + harvested kernel return values."""
        hot = {24, 36, 40, 4, 8}          # CREATE access/disp/copts ; WRITE length/offset
        try:
            recs = self._records()
            body = self._create_body("i2s_victim", 0x12019F, DISP_OPEN_IF,
                                      FILE_NON_DIRECTORY_FILE)
            for off in self._i2s_map(body, recs):
                hot.add(off)
        except Exception:
            pass
        vals = set(self._ret_acc)
        for access, disp, copts, _ in self.DANGEROUS:
            vals.update((access, disp, copts))
        vals.update((0, 1, 0x7fffffff, 0x80000000, 0xffffffff, WRITE_DESIRE_MASK,
                     FILE_DELETE_ON_CLOSE, FILE_WRITE_DATA, FILE_DELETE, 0x02000000,
                     112, 113, 0xffffffffffffffff))
        nh, nv = write_feedback(hot, vals)
        print(f"  [arbiter] distilled g_fb -> {nh} hot offsets + {nv} values "
              f"(FUZZDB/fb.bin, host-durable) — steers next round's mutate_i2s",
              flush=True)

    def _records(self):
        n = self.lib.pfz_get_records(self._recbuf, 4096)
        return [self._recbuf[i] for i in range(n)]

    def _fid(self):
        fb = ctypes.create_string_buffer(16)
        return bytes(fb.raw[:16]) if self.lib.pfz_probe_get_fid(fb) == 0 else None

    @staticmethod
    def _create_body(name, access, disposition, coptions, share=0x7, fileattr=0x80):
        nm = name.encode("utf-16-le")
        b = bytearray(56 + len(nm))
        struct.pack_into("<H", b, 0, 57)
        struct.pack_into("<I", b, 24, access)
        struct.pack_into("<I", b, 28, fileattr)
        struct.pack_into("<I", b, 32, share)
        struct.pack_into("<I", b, 36, disposition)
        struct.pack_into("<I", b, 40, coptions)
        struct.pack_into("<H", b, 44, 120)          # NameOffset (from SMB2 hdr)
        struct.pack_into("<H", b, 46, len(nm))      # NameLength
        b[56:56 + len(nm)] = nm
        return bytes(b)

    @staticmethod
    def _close_body(fid):
        b = bytearray(24)
        struct.pack_into("<H", b, 0, 24)
        b[8:24] = fid
        return bytes(b)

    @staticmethod
    def _write_body(fid, offset, data):
        b = bytearray(48 + len(data))
        struct.pack_into("<H", b, 0, 49)
        struct.pack_into("<H", b, 2, 112)           # DataOffset (from SMB2 hdr)
        struct.pack_into("<I", b, 4, len(data))     # Length
        struct.pack_into("<Q", b, 8, offset & 0xFFFFFFFFFFFFFFFF)
        b[16:32] = fid
        b[48:48 + len(data)] = data
        return bytes(b)

    # ---- input-to-state correspondence ---------------------------------------
    def _i2s_map(self, body, recs):
        """Input-to-state map for the oracle — delegates to the shared primitive
        (single implementation, now also used by the live Phase 3 directed loop)."""
        return i2s_correspondence(body, recs, self.tmap)

    # ---- contract oracle ------------------------------------------------------
    def _create_flag_calls(self, recs):
        calls = {}
        for r in recs:
            if r.type != 0xE or self.tmap.whatis(r.pc) != "smb2_create_open_flags":
                continue
            c = calls.setdefault(r.seq, {})
            v = r.vals[0] & 0xFFFFFFFF
            if   r.arg_idx == 0: c["file_present"] = r.vals[0] & 1
            elif r.arg_idx == 1: c["access"] = v
            elif r.arg_idx == 2: c["disposition"] = v
            elif r.arg_idx == 4: c["coptions"] = v
        return list(calls.values())

    @staticmethod
    def _violations(access, disposition, coptions, file_present):
        out = []
        disp = disposition & 0x7
        is_dir = bool(coptions & FILE_DIRECTORY_FILE)
        if (file_present and not is_dir and disp in TRUNC_DISPOSITIONS
                and not (access & WRITE_DESIRE_MASK)):
            out.append(("OVERWRITE_WITHOUT_WRITE", "MS-SMB2 3.3.5.9",
                        "O_TRUNC disposition granted without FILE_WRITE_DATA"))
        if (coptions & FILE_DELETE_ON_CLOSE) and not (access & FILE_DELETE):
            out.append(("DELETE_ON_CLOSE_WITHOUT_DELETE", "MS-SMB2 3.3.5.9",
                        "DELETE_ON_CLOSE granted without DELETE access"))
        return out

    def _emit(self, kind, spec, detail, sent, body, status, recs):
        # BLAKE2b of the exact bug-triggering PDU — the canonical identity for
        # this finding (dedups distinct triggers even within the same kind).
        bug_id = corpus_bug_id(kind, body)
        if bug_id in _emitted_findings:
            return
        _emitted_findings.add(bug_id)
        # dataflow provenance: did smb2_create_open_flags actually see these args?
        observed = self._create_flag_calls(recs)
        i2s = self._i2s_map(body, recs)
        try:
            FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
            rec = {
                "kind": kind, "spec": spec, "detail": detail,
                "blake2b": bug_id,
                "ntstatus": f"0x{status:08x}", "succeeded": status == 0,
                "share": "privtest", "worker_octet": self.octet,
                "sent": {k: f"0x{v:08x}" for k, v in sent.items()},
                "create_pdu_hex": body.hex(),
                "dataflow_args_observed": [
                    {k: f"0x{v:x}" for k, v in o.items()} for o in observed],
                "i2s_input_to_state": [
                    {"input_offset": off, "value": f"0x{v:x}", "width": w,
                     "func": fn, "arg_idx": ai}
                    for off, (v, w, fn, ai) in sorted(i2s.items())
                    if fn == "smb2_create_open_flags"],
                "symbolized": bool(self.tmap.ranges),
            }
            fn = FINDINGS_DIR / f"{kind.lower()}_{bug_id[:12]}.json"
            fn.write_text(json.dumps(rec, indent=2))
            print(f"  [ORACLE] {kind} ({spec}) — ksmbd returned "
                  f"{'STATUS_SUCCESS' if status == 0 else hex(status)}; "
                  f"reproducer → {fn}", flush=True)
            if observed:
                print(f"           dataflow proof: smb2_create_open_flags("
                      f"access={rec['dataflow_args_observed'][0].get('access','?')}, "
                      f"disposition={rec['dataflow_args_observed'][0].get('disposition','?')}, "
                      f"coptions={rec['dataflow_args_observed'][0].get('coptions','?')})", flush=True)
        except Exception as e:
            print(f"  [ORACLE] emit failed: {e!r}", flush=True)

    # ---- the always-on hunt ---------------------------------------------------
    # (DesiredAccess, CreateDisposition, CreateOptions, label) — read-only handle
    # combined with a write/delete-implying option. READ access = no write bit.
    RO = FILE_READ_DATA | FILE_READ_ATTRIBUTES
    DANGEROUS = [
        (RO, DISP_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, "overwrite_if_readonly"),
        (RO, DISP_OVERWRITE,    FILE_NON_DIRECTORY_FILE, "overwrite_readonly"),
        (RO, DISP_SUPERSEDE,    FILE_NON_DIRECTORY_FILE, "supersede_readonly"),
        (RO, DISP_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, "doc_file_readonly"),
        (RO, DISP_OPEN, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,     "doc_dir_readonly"),
    ]

    def _positive_control(self, full):
        """Positive control (#2): prove the oracle's detect→emit chain fires, so a
        silent CREATE sweep means 'ksmbd correctly rejected', NOT 'oracle blind'.

          (a) Predicate self-test — a known RO+OVERWRITE tuple MUST flag and a safe
              read+write tuple MUST NOT; if either is wrong the detection logic is
              broken and silence is meaningless.
          (b) Live control — open the victim with FILE_READ_DATA only, then WRITE
              through that handle. ksmbd MUST reject on the granted-access check; if
              it ACCEPTS (status 0) that is a genuine LPE finding. Either outcome
              exercises the full transport+records+emit path end to end.
        """
        ro = FILE_READ_DATA | FILE_READ_ATTRIBUTES
        must_flag = self._violations(ro, DISP_OVERWRITE, FILE_NON_DIRECTORY_FILE,
                                     file_present=1)
        must_not = self._violations(FILE_READ_DATA | FILE_WRITE_DATA, DISP_OVERWRITE,
                                    FILE_NON_DIRECTORY_FILE, file_present=1)
        detect_ok = (any(k == "OVERWRITE_WITHOUT_WRITE" for k, _, _ in must_flag)
                     and not must_not)
        print(f"  [oracle] positive-control predicate self-test: "
              f"{'PASS' if detect_ok else '!!! FAIL — detection logic broken, silence is meaningless'}",
              flush=True)

        # Pre-create the RO victim as owner so DISP_OPEN_IF finds/creates it, then
        # reopen it with a read-only handle for the write-through test.
        self._probe(0x0005, self._create_body("i2s_roctl", full, DISP_OPEN_IF,
                                               FILE_NON_DIRECTORY_FILE))
        seed = self._fid()
        if seed:
            self._probe(0x0006, self._close_body(seed))
        self._probe(0x0005, self._create_body("i2s_roctl", ro, DISP_OPEN,
                                               FILE_NON_DIRECTORY_FILE))
        rfid = self._fid()
        if not rfid:
            print("  [oracle] positive-control: could not open read-only handle "
                  "(skipped live control)", flush=True)
            return
        body = self._write_body(rfid, 0, b"RO-HANDLE-WRITE")
        resp, status = self._probe(0x0009, body)
        recs = self._records()
        st = (status & 0xFFFFFFFF) if status is not None else 0xFFFFFFFF
        accepted = status == 0
        print(f"  [oracle] positive-control WRITE via read-only handle: "
              f"NTSTATUS=0x{st:08x} "
              f"{'ACCEPTED → CONTRACT VIOLATION' if accepted else 'rejected (correct)'}",
              flush=True)
        if accepted:
            self._emit("WRITE_THROUGH_RO_HANDLE", "MS-SMB2 3.3.5.13",
                       "WRITE succeeded on a handle opened with FILE_READ_DATA only "
                       "(no FILE_WRITE_DATA) — granted access not honored",
                       {"access": ro}, body, status, recs)
        self._probe(0x0006, self._close_body(rfid))

    # ---- SMB2 opcodes + READ helpers (used by the lifetime/lease/race oracles) --
    _LOGOFF, _TREE_DISCONNECT = 0x0002, 0x0004
    _CREATE, _CLOSE, _READ, _WRITE = 0x0005, 0x0006, 0x0008, 0x0009
    _LEASE_R, _LEASE_H, _LEASE_W = 0x01, 0x02, 0x04   # MS-SMB2 2.2.13.2.8

    @staticmethod
    def _read_body(fid, offset, length):
        b = bytearray(49)
        struct.pack_into("<H", b, 0, 49)            # StructureSize
        struct.pack_into("<I", b, 4, length)        # Length
        struct.pack_into("<Q", b, 8, offset & 0xFFFFFFFFFFFFFFFF)
        b[16:32] = fid
        struct.pack_into("<I", b, 32, 1)            # MinimumCount
        return bytes(b)

    @staticmethod
    def _read_payload(resp):
        """Extract the data bytes from a READ response (DataOffset/DataLength are
        SMB2-header-absolute). Bounds-checked; returns None on any inconsistency."""
        try:
            if resp is None or len(resp) < 64 + 16:
                return None
            doff = resp[64 + 2]                       # DataOffset (1 byte)
            dlen = struct.unpack_from("<I", resp, 64 + 4)[0]
            if doff == 0 or dlen == 0 or doff + dlen > len(resp):
                return None
            return resp[doff:doff + dlen]
        except Exception:
            return None

    def _probe_reset(self, share=b"privtest"):
        """Rebuild a clean authenticated session (used between destructive
        sequences in the lifetime oracle). True on success."""
        try:
            return self.lib.pfz_probe_reconnect(share) == 0
        except Exception:
            return False

    # ---- lifetime / use-after-teardown oracle (UAF hunt) ----------------------
    def _teardown_oracle(self, full):
        """Provoke use-after-free / stale-reference bugs in session & tree-connect
        teardown — historically the highest-CVE-density area of ksmbd.

        Each sequence opens a handle, destroys the object that owns it
        (TREE_DISCONNECT frees the tree_conn; LOGOFF frees the session plus all its
        trees+files), then USES the now-dangling FileId. Correct ksmbd rejects the
        dangling op with an error NTSTATUS and never touches freed memory. Two
        detectable failures:
          * logic — the dangling op returns STATUS_SUCCESS (0): the object was
            honored after teardown (emitted here);
          * memory — a KASAN use-after-free / double-free splat on the serial
            console (host-side grep), attributed by the BEGIN/END markers we print.
        The session is rebuilt after every sequence.
        """
        print("  [uaf] session/tree teardown lifetime oracle", flush=True)
        td = struct.pack("<HH", 4, 0)   # LOGOFF / TREE_DISCONNECT body (StructSize=4)
        for label, teardown_cmd, obj in (
                ("use_after_tree_disconnect", self._TREE_DISCONNECT, "tree_conn"),
                ("use_after_logoff",          self._LOGOFF,          "session")):
            if not self._probe_reset():
                print(f"  [uaf] {label}: probe reconnect failed, skipping", flush=True)
                continue
            self._probe(self._CREATE, self._create_body(
                "uaf_victim", full, DISP_OPEN_IF, FILE_NON_DIRECTORY_FILE))
            fid = self._fid()
            if not fid:
                print(f"  [uaf] {label}: could not open victim handle, skipping", flush=True)
                continue
            print(f"  [uaf] --- BEGIN {label} (freeing {obj} with an open fid) ---", flush=True)
            self._probe(teardown_cmd, td)
            wresp, wst = self._probe(self._WRITE, self._write_body(fid, 0, b"UAF-DANGLING-WRITE"))
            cresp, cst = self._probe(self._CLOSE, self._close_body(fid))
            wsv = (wst & 0xFFFFFFFF) if wst is not None else 0xFFFFFFFF
            csv = (cst & 0xFFFFFFFF) if cst is not None else 0xFFFFFFFF
            conn_dead = (wresp is None and cresp is None)
            print(f"  [uaf] --- END {label}: WRITE=0x{wsv:08x} CLOSE=0x{csv:08x}"
                  f"{' CONN-DROPPED(possible crash)' if conn_dead else ''} ---", flush=True)
            if wst == 0 or cst == 0:
                recs = self._records()
                which = "WRITE" if wst == 0 else "CLOSE"
                self._emit("USE_AFTER_TEARDOWN", "MS-SMB2 3.3.5.6/3.3.5.7",
                           f"{which} on a FileId succeeded after "
                           f"{label.replace('use_after_', '').upper()} freed its {obj} — "
                           f"stale handle honored (use-after-free / lifetime bug)",
                           {"access": full},
                           self._write_body(fid, 0, b"UAF-DANGLING-WRITE") if wst == 0
                           else self._close_body(fid), wst if wst == 0 else cst, recs)
        # double-teardown -> double-free candidates
        for label, teardown_cmd in (("double_tree_disconnect", self._TREE_DISCONNECT),
                                     ("double_logoff", self._LOGOFF)):
            if not self._probe_reset():
                continue
            print(f"  [uaf] --- {label} (double teardown -> double-free candidate) ---", flush=True)
            _, s1 = self._probe(teardown_cmd, td)
            r2, s2 = self._probe(teardown_cmd, td)
            s1v = (s1 & 0xFFFFFFFF) if s1 is not None else 0xFFFFFFFF
            s2v = (s2 & 0xFFFFFFFF) if s2 is not None else 0xFFFFFFFF
            print(f"  [uaf] {label}: first=0x{s1v:08x} second=0x{s2v:08x}"
                  f"{' CONN-DROPPED(possible crash)' if r2 is None else ''}", flush=True)
        self._probe_reset()   # leave a clean session behind

    # ---- lease-grant contract oracle ------------------------------------------
    def _lease_create_body(self, name, access, disp, copts, lease_key, lease_state):
        """CREATE body (after the 64-byte SMB2 header) carrying a spec-correct v2
        RqLs create context requesting @lease_state. Header-relative offsets are
        absolute (name at 120); the context is 8-aligned after the name."""
        nm = name.encode("utf-16-le")
        NAME_ABS = 120
        ctx_abs = (NAME_ABS + len(nm) + 7) & ~7
        body_len = (ctx_abs - 64) + 76
        b = bytearray(body_len)
        struct.pack_into("<H", b, 0, 57)
        struct.pack_into("<I", b, 24, access)
        struct.pack_into("<I", b, 28, 0x80)          # FILE_ATTRIBUTE_NORMAL
        struct.pack_into("<I", b, 32, 0x7)           # ShareAccess R|W|D
        struct.pack_into("<I", b, 36, disp)
        struct.pack_into("<I", b, 40, copts)
        struct.pack_into("<H", b, 44, NAME_ABS)
        struct.pack_into("<H", b, 46, len(nm))
        struct.pack_into("<I", b, 48, ctx_abs)        # CreateContextsOffset (SMB2-abs)
        struct.pack_into("<I", b, 52, 76)             # CreateContextsLength
        b[56:56 + len(nm)] = nm
        c = ctx_abs - 64                              # context start, body-relative
        struct.pack_into("<I", b, c + 0, 0)           # Next
        struct.pack_into("<H", b, c + 4, 16)          # NameOffset
        struct.pack_into("<H", b, c + 6, 4)           # NameLength
        struct.pack_into("<H", b, c + 8, 0)           # Reserved
        struct.pack_into("<H", b, c + 10, 24)         # DataOffset
        struct.pack_into("<I", b, c + 12, 52)         # DataLength (v2 lease)
        b[c + 16:c + 20] = b"RqLs"
        b[c + 24:c + 40] = lease_key
        struct.pack_into("<I", b, c + 40, lease_state & 0x7)
        return bytes(b)

    @staticmethod
    def _parse_granted_lease(resp):
        """Granted LeaseState from a CREATE response's RqLs context, else None.
        Every offset is bounds-checked; an absent/malformed context yields None."""
        try:
            if resp is None or len(resp) < 64 + 88:
                return None
            cco = struct.unpack_from("<I", resp, 64 + 80)[0]    # SMB2-abs
            ccl = struct.unpack_from("<I", resp, 64 + 84)[0]
            if cco == 0 or ccl == 0 or cco + 16 > len(resp):
                return None
            off = cco
            for _ in range(8):
                if off + 16 > len(resp):
                    return None
                nxt = struct.unpack_from("<I", resp, off)[0]
                noff = struct.unpack_from("<H", resp, off + 4)[0]
                nlen = struct.unpack_from("<H", resp, off + 6)[0]
                doff = struct.unpack_from("<H", resp, off + 10)[0]
                dlen = struct.unpack_from("<I", resp, off + 12)[0]
                name = (resp[off + noff:off + noff + nlen]
                        if off + noff + nlen <= len(resp) else b"")
                if name == b"RqLs" and dlen >= 20 and off + doff + 20 <= len(resp):
                    return struct.unpack_from("<I", resp, off + doff + 16)[0]
                if nxt == 0:
                    return None
                off += nxt
        except Exception:
            return None
        return None

    @staticmethod
    def _lease_str(x):
        return "".join(c for c, bit in (("R", 1), ("H", 2), ("W", 4)) if x & bit) or "-"

    def _lease_oracle(self, full):
        """Lease-grant contract: the state ksmbd GRANTS must be a subset of what
        was requested (MS-SMB2 3.3.5.9.11) and internally consistent (write-caching
        implies read-caching). A granted bit that was not requested, or W-without-R,
        is a lease-state-machine defect (stale-cache / data-corruption class)."""
        if not self._probe_reset():
            print("  [lease] probe reconnect failed, skipping", flush=True)
            return
        key = b"\xa1" * 16
        self._probe(self._CREATE, self._create_body(
            "lease_victim", full, DISP_OPEN_IF, FILE_NON_DIRECTORY_FILE))
        f0 = self._fid()
        if f0:
            self._probe(self._CLOSE, self._close_body(f0))
        for label, req in (("RWH", self._LEASE_R | self._LEASE_H | self._LEASE_W),
                           ("RH",  self._LEASE_R | self._LEASE_H),
                           ("R",   self._LEASE_R)):
            body = self._lease_create_body("lease_victim", full, DISP_OPEN,
                                           FILE_NON_DIRECTORY_FILE, key, req)
            resp, status = self._probe(self._CREATE, body)
            granted = self._parse_granted_lease(resp)
            recs = self._records()
            fid = self._fid()
            if fid:
                self._probe(self._CLOSE, self._close_body(fid))
            stv = (status & 0xFFFFFFFF) if status is not None else 0xFFFFFFFF
            if granted is None:
                print(f"  [lease] request={label}: no lease granted / unparsable "
                      f"(status=0x{stv:08x})", flush=True)
                continue
            extra = granted & ~req & 0x7
            w_no_r = bool(granted & self._LEASE_W) and not (granted & self._LEASE_R)
            print(f"  [lease] request={label}({self._lease_str(req)}) "
                  f"granted={self._lease_str(granted)}"
                  f"{' EXTRA=' + self._lease_str(extra) if extra else ''}"
                  f"{' W-WITHOUT-R' if w_no_r else ''}", flush=True)
            if extra or w_no_r:
                detail = (f"ksmbd granted lease {self._lease_str(granted)} for a "
                          f"{self._lease_str(req)} request"
                          + (f"; extra bits {self._lease_str(extra)} never requested" if extra else "")
                          + ("; write-caching without read-caching" if w_no_r else ""))
                self._emit("LEASE_STATE_OVERGRANT", "MS-SMB2 3.3.5.9.11", detail,
                           {"requested": req, "granted": granted}, body, status, recs)

    # ---- race state-divergence oracle (fixes fire-and-forget races) -----------
    def _race_integrity_oracle(self, full):
        """A fire-and-forget race only surfaces bugs if it happens to crash. Add a
        state-divergence check: write a known pattern, run a race that could tear
        server-side file state, then read it back and compare. A silent mismatch =
        the race corrupted state without a crash."""
        if not self._probe_reset():
            return
        fname = "race_integrity"
        pattern = bytes(((i * 7) & 0xFF) for i in range(256))
        self._probe(self._CREATE, self._create_body(
            fname, full, DISP_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE))
        wfid = self._fid()
        if not wfid:
            return
        self._probe(self._WRITE, self._write_body(wfid, 0, pattern))
        self._probe(self._CLOSE, self._close_body(wfid))
        # best-effort: drive a real oplock race across pool connections
        try:
            if self.lib.pfz_pool_init_authed(2) >= 0:
                self.lib.pfz_pool_oplock_race(fname.encode())
        except Exception:
            pass
        # read the pattern back through a fresh handle
        self._probe_reset()
        self._probe(self._CREATE, self._create_body(
            fname, full, DISP_OPEN, FILE_NON_DIRECTORY_FILE))
        rfid = self._fid()
        if not rfid:
            return
        rb = self._read_body(rfid, 0, len(pattern))
        resp, status = self._probe(self._READ, rb)
        recs = self._records()
        self._probe(self._CLOSE, self._close_body(rfid))
        got = self._read_payload(resp)
        if status == 0 and got is not None and got != pattern:
            print(f"  [race] STATE DIVERGENCE: wrote {len(pattern)}B pattern, "
                  f"read back {len(got)}B that differ", flush=True)
            self._emit("RACE_STATE_DIVERGENCE", "MS-SMB2 3.3.5.9",
                       f"file content diverged after an oplock race: wrote "
                       f"{len(pattern)} bytes of a known pattern, read back "
                       f"{len(got)} differing bytes without a crash",
                       {"len": len(pattern)}, rb, status, recs)
        else:
            print("  [race] integrity check: content stable after race", flush=True)

    # ---- fragmented-framing pass (fixes loopback-only short-read coverage) -----
    def _frag_pass(self, full):
        """Re-issue a CREATE/WRITE/CLOSE cycle with the PDU split across TCP
        segments (pfz_probe_send_frag) so ksmbd_tcp_readv()'s partial-read loop —
        which a single loopback write() coalesces away — actually runs."""
        if not self._probe_reset():
            return
        buf = ctypes.create_string_buffer(8192)
        body = self._create_body("frag_victim", full, DISP_OPEN_IF, FILE_NON_DIRECTORY_FILE)
        try:
            r = self.lib.pfz_probe_send_frag(self._CREATE, body, len(body), buf, 8192, 8)
        except Exception as e:
            print(f"  [frag] send_frag unavailable ({e!r})", flush=True)
            return
        st = int.from_bytes(buf.raw[8:12], "little") if r >= 12 else 0xFFFFFFFF
        fid = self._fid()
        if fid:
            wb = self._write_body(fid, 0, b"FRAGMENTED-WRITE")
            self.lib.pfz_probe_send_frag(self._WRITE, wb, len(wb), buf, 8192, 6)
            self._probe(self._CLOSE, self._close_body(fid))
        print(f"  [frag] segmented CREATE reassembled by ksmbd_tcp_readv: "
              f"NTSTATUS=0x{st & 0xFFFFFFFF:08x} "
              f"{'(conn survived)' if r >= 12 else '(CONN-DROPPED — check console)'}",
              flush=True)

    def _cross_user_oracle(self):
        """REAL write-side LPE oracle (#39) — replaces the owner-on-own-file check,
        which can only ever emit false positives (findings/TRIAGE-contract-oracle.md).
        The victim is owned by root (uid 0); on [privtest] ksmbd maps `fuzz` to a
        non-root uid (65535/nobody — no system `fuzz` user), so POSIX genuinely
        denies write/delete. Violations are judged by EFFECT on the backing FS
        (data destroyed / file unlinked), NOT by status==0 — ksmbd can return
        SUCCESS while POSIX silently prevents the destructive effect (e.g. the
        create-path O_TRUNC is a no-op). A real hit means ksmbd bypassed POSIX
        (acted as root, or skipped a check) = genuine integrity/LPE bug."""
        import pathlib
        PRIV = pathlib.Path("/tmp/ksmbd_priv")
        xdir, victim = PRIV / "xu", PRIV / "xu" / "rov"
        SECRET = b"PRECIOUS_XUSER_DATA"

        def _plant():
            xdir.mkdir(exist_ok=True)
            victim.write_bytes(SECRET)
            os.chown(victim, 0, 0); os.chmod(victim, 0o644)
            os.chown(xdir, 0, 0); os.chmod(xdir, 0o755)

        try:
            _plant()
        except Exception as e:
            print(f"  [xuser] setup failed ({e!r}) — cross-user oracle skipped "
                  f"(needs root in guest)", flush=True)
            return

        # Sanity: confirm fuzz is a non-root uid on [privtest]; else the POSIX gate
        # is a no-op and a 'violation' would be inconclusive.
        self._probe(self._CREATE, self._create_body(
            "xu_uidcheck", 0x12019F, DISP_OPEN_IF, FILE_NON_DIRECTORY_FILE))
        f = self._fid()
        if f:
            self._probe(self._CLOSE, self._close_body(f))
        pf = PRIV / "xu_uidcheck"
        fuzz_uid = pf.stat().st_uid if pf.exists() else -1
        if fuzz_uid == 0:
            print("  [xuser] fuzz maps to uid 0 on [privtest] — POSIX cannot "
                  "distinguish it; cross-user oracle inconclusive, skipping", flush=True)
            return
        print(f"  [xuser] victim root:root 0644 (parent 0755), fuzz→uid {fuzz_uid} "
              f"(non-root) — POSIX gate active; judging by EFFECT", flush=True)

        def _check(kind, spec, detail, body, st, gone_or_changed, ok_msg):
            st = (st & 0xFFFFFFFF) if st is not None else 0xFFFFFFFF
            if gone_or_changed:
                print(f"  [xuser] !!! REAL VIOLATION: {kind} as uid {fuzz_uid} "
                      f"(NTSTATUS=0x{st:08x})", flush=True)
                self._emit(kind, spec, detail,
                           {"access": self.RO, "uid": fuzz_uid}, body, st,
                           self._records())
            else:
                print(f"  [xuser] {ok_msg} (NTSTATUS=0x{st:08x}) — correct", flush=True)

        # (1) OVERWRITE: read-only handle + truncating disposition.
        body = self._create_body("xu\\rov", self.RO, DISP_OVERWRITE_IF,
                                 FILE_NON_DIRECTORY_FILE)
        _, st = self._probe(self._CREATE, body)
        f = self._fid()
        if f:
            self._probe(self._CLOSE, self._close_body(f))
        after = victim.read_bytes() if victim.exists() else b""
        _check("XUSER_OVERWRITE_WITHOUT_WRITE", "MS-SMB2 3.3.5.9 / POSIX",
               "read-only handle truncated a root-owned 0644 file", body, st,
               after != SECRET, "overwrite: root data intact")
        try: _plant()
        except Exception: pass

        # (2) DELETE_ON_CLOSE: read-only handle, parent dir unwritable to fuzz.
        body = self._create_body("xu\\rov", self.RO, DISP_OPEN,
                                 FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)
        _, st = self._probe(self._CREATE, body)
        f = self._fid()
        if f:
            self._probe(self._CLOSE, self._close_body(f))
        _check("XUSER_DELETE_WITHOUT_PERMISSION", "MS-SMB2 3.3.5.9 / POSIX",
               "delete-on-close unlinked a root-owned file from a 0755 root dir",
               body, st, not victim.exists(), "delete-on-close: root file survived")
        try: _plant()
        except Exception: pass

        # (3) direct SMB2_WRITE on a read-only handle.
        body = self._create_body("xu\\rov", self.RO, DISP_OPEN, FILE_NON_DIRECTORY_FILE)
        self._probe(self._CREATE, body)
        f = self._fid()
        if f:
            self._probe(self._WRITE, self._write_body(f, 0, b"HACKED"))
            self._probe(self._CLOSE, self._close_body(f))
        after = victim.read_bytes() if victim.exists() else b""
        _check("XUSER_WRITE_WITHOUT_WRITE", "MS-SMB2 3.3.5.13 / POSIX",
               "SMB2_WRITE on a read-only handle modified a root-owned file", body, 0,
               after != SECRET, "direct write on RO handle: root data intact")

    # Deterministic sweep — run it once per worker process, not every cycle.
    _ran = False

    def run(self):
        if DataflowDirector._ran:
            return self.ready
        DataflowDirector._ran = True

        rc = self.lib.pfz_probe_init_share(b"privtest")
        if rc != 0:
            print(f"  [director] probe auth to [privtest] FAILED (rc={rc}) — oracle "
                  f"disabled. Check: 'fuzz' user exists, [privtest] share present, "
                  f"NTLMv2 (see [probe] lines above).", flush=True)
            return False
        self.ready = True
        print(f"  [director] authenticated to [privtest]; running write-side contract "
              f"oracle (kallsyms {f'ON — {self.tmap.resolved}/{len(TargetMap.TARGETS)} targets resolved' if self.tmap.ranges else 'OFF — provenance limited'})",
              flush=True)

        full = (FILE_READ_DATA | FILE_WRITE_DATA | FILE_DELETE |
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        # Pre-create the victim file (writable) so OVERWRITE_IF/DELETE see it present.
        self._probe(0x0005, self._create_body("i2s_victim", full, DISP_OPEN_IF,
                                               FILE_NON_DIRECTORY_FILE))
        fid = self._fid()
        if fid:
            self._probe(0x0009, self._write_body(fid, 0, b"PRECIOUS DATA"))
            self._probe(0x0006, self._close_body(fid))

        nflag = 0
        for access, disp, copts, label in self.DANGEROUS:
            name = "i2s_victim" if not (copts & FILE_DIRECTORY_FILE) else "i2s_victim_dir"
            if copts & FILE_DIRECTORY_FILE:   # ensure a victim directory exists
                self._probe(0x0005, self._create_body(name, full, DISP_OPEN_IF,
                                                       FILE_DIRECTORY_FILE))
                d = self._fid()
                if d:
                    self._probe(0x0006, self._close_body(d))
            body = self._create_body(name, access, disp, copts)
            resp, status = self._probe(0x0005, body)
            recs = self._records()
            sent = {"access": access, "disposition": disp, "coptions": copts}
            viols = self._violations(access, disp, copts, file_present=1)
            accepted = status == 0
            flagged = bool(viols) and accepted
            st = (status & 0xFFFFFFFF) if status is not None else 0xFFFFFFFF
            print(f"  [director] CREATE {label}: NTSTATUS=0x{st:08x} "
                  f"{'ACCEPTED' if accepted else 'rejected'}"
                  f"{' → owner-probe (coverage only, NOT a violation)' if flagged else ''}", flush=True)
            if verbose_on():
                obs = self._create_flag_calls(recs)
                i2s = {o: hex(v) for o, (v, w, fn, ai) in self._i2s_map(body, recs).items()
                       if fn == "smb2_create_open_flags"}
                vlog(f"director/{label}: dataflow smb2_create_open_flags args="
                     f"{[{k: hex(v) for k, v in o.items()} for o in obs]} "
                     f"i2s byte→arg offsets={i2s}")
            # This owner-on-own-file sweep drives smb2_create_open_flags coverage +
            # i2s mapping, but it CANNOT prove a violation: fuzz OWNS these victims,
            # so ksmbd/POSIX legitimately grants every op (all 5 prior "findings"
            # were false positives — see findings/TRIAGE-contract-oracle.md). Do NOT
            # emit here; the real, effect-verified check is _cross_user_oracle().
            if flagged:
                nflag += len(viols)
            fid = self._fid()
            if fid and resp is not None:
                self._probe(0x0006, self._close_body(fid))

        print(f"  [director] owner CREATE sweep done: {nflag} contract-shaped op(s) "
              f"(coverage/i2s only — NOT violations; fuzz owns these files).", flush=True)

        # REAL write-side LPE oracle: root-owned victim, judged by EFFECT (#39).
        self._cross_user_oracle()

        # Positive control — makes a silent sweep interpretable (#2).
        self._positive_control(full)

        # ksmbd_vfs_write I2S: open writable, drive count/pos to boundaries so the
        # offset/length input bytes map to ksmbd_vfs_write() args. OOB surfaces via
        # KASAN — check dmesg right after the boundary sweep so we attribute it.
        self._probe(0x0005, self._create_body("i2s_victim", full, DISP_OPEN_IF,
                                               FILE_NON_DIRECTORY_FILE))
        wfid = self._fid()
        if wfid:
            BOUND = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                     0xFFFFFFFFFFFFFFFF, 1 << 40, (1 << 63)]
            for off in BOUND:
                body = self._write_body(wfid, off, b"A" * 64)
                self._probe(0x0009, body)
                self._i2s_map(body, self._records())  # offset→ksmbd_vfs_write arg
            self._probe(0x0006, self._close_body(wfid))
            # Any KASAN/OOB from the boundary writes surfaces on the serial
            # console (host-side grep), not via an in-process dmesg read.

        # New oracles (run once per worker, after the write-side sweep). Each
        # rebuilds its own clean session, so ordering is independent; the
        # destructive teardown oracle runs last. KASAN/lockdep from any of these
        # lands on the serial console with the [uaf]/[lease]/[race]/[frag] markers.
        self._lease_oracle(full)          # lease-grant contract (task #4)
        self._race_integrity_oracle(full) # race state-divergence (fire-and-forget fix)
        self._frag_pass(full)             # loopback short-read framing (limitation #2)
        self._teardown_oracle(full)       # session/tree UAF (task #2, highest-yield)
        self._flush_return_tokens()       # RedQueen return-value dict (upgrade 3)
        self._distill()                   # arbiter: write g_fb for next round's mutate_i2s
        return True


def run_dataflow_director(lib, worker_octet=1):
    """Always-on write-side oracle + I2S probe. Safe no-op if the probe can't
    authenticate (e.g. [privtest] share absent)."""
    try:
        return DataflowDirector(lib, worker_octet).run()
    except Exception as e:
        import traceback
        print(f"  [director] error: {e!r}", flush=True)
        traceback.print_exc()
        return False


# ─── Combination fuzzing phase (needs -procs >= 2) ────────────────────────────
# Each worker process hammers ONE operation; the phase runs every
# combinations_with_replacement of the operation set across the N procs so that,
# e.g., {vfs_write ∥ kerberos} run *concurrently* against ksmbd to surface
# cross-operation interaction / state-corruption bugs (KASAN). Ordered
# high-priority (privileged write) → low-priority (negotiate/kerberos).

# Combination procedures, write/LPE-relevant first. negotiate/kerberos are
# deliberately EXCLUDED: they are low-priority control-plane ops and the
# negotiate parser floods thousands of deassemble_neg_contexts errors per round
# while adding no write-side coverage.


# -target → which COMBO_TARGETS participate (mirrors the grain TARGET_MAP so
# focusing the campaign also focuses the combination space — e.g. -target write
# only combines write-side ops, never negotiate/kerberos).


PERSISTENT_CORPUS = Path('/tmp/ksmbdzzer_corpus_persistent')


def cmd_validate(args):
    """Run a fast validation campaign checking that known CVE patterns trigger bugs.
    Intended for older kernels (6.6-6.11) where the bugs are unpatched."""
    print("=== ksmbdzzer VALIDATE mode ===")
    print(f"Target: detect known CVE patterns on current kernel")
    print()

    # Init
    cmd_init(install_deps=False)

    # Run grains only (no full discovery — just check if bugs trigger)
    import sys; sys.path.insert(0, str(SCRIPT_DIR))
    from grain import generate_all_grains, run_grains

    grains = generate_all_grains([0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF])
    print(f"[*] Generated {len(grains)} grains")

    _max = args.time if hasattr(args, 'time') and args.time else 60
    print(f"[*] Running each grain until saturation (ceiling {_max}s)...")
    crashes = run_grains(grains, sat_ratio=0.02, max_time=_max, parallelism=4)

    # Also check dmesg
    bugs = os.popen("dmesg | grep -cE 'BUG: KASAN|BUG: unable to handle|general protection fault|stack-protector|refcount_t:.*underflow|refcount_t:.*overflow|double-free|Oops|UBSAN:.*ksmbd|UBSAN:.*smb|BUG:.*ksmbd|BUG:.*smb|WARNING:.*ksmbd|WARNING:.*smb|possible circular.*ksmbd|sleeping.*atomic.*ksmbd|Kernel panic' 2>/dev/null").read().strip()
    bug_count = int(bugs) if bugs.isdigit() else 0

    print()
    if crashes or bug_count > 0:
        print(f"!!! VALIDATION: {len(crashes)} grain crashes + {bug_count} kernel bugs detected !!!")
        os.system("dmesg | tail -60 | grep -B2 -A15 -E 'KASAN|UBSAN|ksmbd|Oops|general protection|refcount_t|stack-protector' | head -45")
    else:
        print(f"VALIDATION: 0 bugs detected — kernel appears patched against tested patterns")
    print(f"Grains tested: dacl_setinfo, stream_oob, ea_alignment, lock_race, "
          f"create_ctx, ndr_rpc, compound, spnego_auth")


def cmd_selftest(args):
    """Pre-P2 grain-VALIDITY gate — the "a grain must work" principle, made measurable.

    Before P2 spends any LibFuzzer budget, run EACH grain a few times straight through
    ctypes (pfz_grain_run → pfz_get_features) and check whether it actually reaches ksmbd
    KERNEL code (produces kcov-dataflow coverage). A grain that yields ZERO kernel PCs on
    every try is not a meaningful fuzz target no matter how many execs it would burn:
      • BAIL  = returned <0 every run → it bailed at a prerequisite (no authed pool, no fid,
                connect/auth failed, share/config missing). It never executed.
      • DEAD  = ran (>=0) but 0 kernel PCs → its PDU never reached a ksmbd handler (rejected
                pre-dispatch, wrong target, or the scenario is inert).
      • WORKS = reached >= --min-pcs kernel PCs → a real, meaningful grain; pcs is its depth.

    This is a seconds-scale filter over the WHOLE fleet (no VM re-boot, no LibFuzzer), so it
    answers "are our N grains meaningful?" directly and cheaply. It requires ksmbd running
    (`ksmbdzzer.py init` first) and the coverage bridge intact (a non-blind kernel — if EVERY
    grain reads 0 PCs, the ksmbd kcov remote hooks are missing, not the grains). Writes the
    meaningful set to grain/WORKING_SUBSET.txt (coverage-desc) for `-t` scoping.
    """
    import time
    lib = _get_lib()                     # loads .so + pfz_init(octet): coverage handle + session + raw sock
    # Per-grain RAW-pool re-establisher. The batch-10+ grains use the raw-socket g_pool[]
    # (pool_ensure_fid / pool_lazy), and the conn-disrupting grains (encrypt, session_setup,
    # smb1_*, sign, oplock_ack, logoff*, tdis*) tear that pool DOWN — and pool_lazy's _tried_n
    # guard deliberately won't re-auth a dead-but-present pool (a throughput choice for fuzz).
    # In a real fuzz run each grain is its OWN process with a fresh pool, so this contamination
    # can't happen; here all grains share ONE process, so a disruptor makes every pool grain
    # AFTER it false-BAIL. Re-establish g_pool[] (pfz_pool_init → pool_connect_one, the raw
    # authed pool these grains actually use) before EACH grain to reproduce the fresh-process
    # isolation and give an accurate WORKS/BAIL split.
    try:
        lib.pfz_pool_init.argtypes = [ctypes.c_int]
        lib.pfz_pool_init.restype = ctypes.c_int
        lib.pfz_pool_fids_ready.restype = ctypes.c_int
        _pool_reset = True
        pn = lib.pfz_pool_init(2)     # one-time establish of the raw g_pool[] (2 conns + fids)
        print(f"{_dts()} [selftest] raw pool ready ({pn} conn); RESET+RETRY on all-repeats-bail "
              f"(heals a socket a conn-disrupting grain closed; re-auths ≈ #disruptors, no storm)", flush=True)
    except Exception as _e:
        _pool_reset = False
        print(f"{_dts()} [selftest] WARN pool API unavailable ({_e!r}) — pool grains may false-BAIL", flush=True)
    n = lib.pfz_grain_count()
    sel = set(args.target) if getattr(args, 'target', None) else None
    # Architectural exclusions — grains that CANNOT produce per-SMB-connection kcov coverage,
    # so the selftest can't measure them (they are NOT broken and STAY in the GRAINS[] registry
    # for real fuzz, which reaches ksmbd via these paths a different way):
    #   ipc  — SMBD_GENL netlink, not an SMB connection → the IP-handle remote hook never fires
    #   rdma — needs the RXE/SMBDirect data-plane, which the loopback selftest can't drive
    # Reported as EXCL and left OUT of the WORKS/DEAD verdict (deactivated from the map's
    # accounting only, per "comment in the map, not remove").
    EXCLUDE = {"ipc", "rdma"}
    repeats = max(1, int(getattr(args, 'repeats', 4)))
    thresh  = max(1, int(getattr(args, 'min_pcs', 1)))
    FEATN = 8192
    FEAT = (ctypes.c_uint32 * FEATN)()
    def _cov():
        # ksmbd's kcov merge (kcov_df_remote_stop) lands AFTER the response is sent, so a
        # single-op grain can read g_df_buf BEFORE the merge → flaky 0. Poll briefly for it
        # (pfz_get_features doesn't reset g_df_buf, so re-reading is safe/idempotent). This
        # closes the async-merge race that made single-op grains flaky-DEAD.
        p = lib.pfz_get_features(FEAT, FEATN)
        for _ in range(6):
            if p > 0:
                break
            time.sleep(0.003)
            p = lib.pfz_get_features(FEAT, FEATN)
        return p
    print(f"{_dts()} [selftest] {n} grains x {repeats} runs — verify each reaches ksmbd kernel "
          f"code (>= {thresh} PC). WORKS=real / DEAD=ran-but-0-cov / BAIL=prereq-failed", flush=True)
    works, dead, bail, excl, skipped = [], [], [], [], 0
    t0 = time.time()
    for i in range(n):
        name = lib.pfz_grain_name(i).decode('ascii', 'replace')
        if sel is not None and name not in sel:
            skipped += 1
            continue
        if name in EXCLUDE:
            # architectural — measurable coverage impossible in the loopback selftest, but the
            # grain stays live for real fuzz. Report and skip the WORKS/DEAD verdict entirely.
            excl.append(name)
            print(f"{_dts()}   [EXCL ] {name:30} (architectural — no per-conn kcov in selftest; "
                  f"stays in fleet for fuzz)", flush=True)
            continue
        best_pcs, best_ret, ran = 0, -99, False
        for k in range(repeats):
            # deterministic-but-varied 64-byte seed per (grain, try) so a few code paths open
            seed = bytes(((i * 131 + k * 17 + j * 7) & 0xFF) for j in range(64))
            ret = lib.pfz_grain_run(i, seed, len(seed))
            pcs = _cov()                              # kernel-PC count (polls past the merge race)
            best_ret = max(best_ret, ret)
            best_pcs = max(best_pcs, pcs)
            if ret >= 0:
                ran = True
        # Bailed on EVERY repeat? A prior conn-disrupting grain (encrypt/session_setup/smb1_*/
        # sign/logoff/tdis) closes the pool SOCKET but leaves has_fid=1, so pool_ensure_fid
        # reuses the stale conn and pool_xact fails on the dead socket → false BAIL. A FULL
        # pfz_pool_init (fresh socket + fid) heals that; retry ONCE. This runs only for a
        # bailed grain and re-heals the pool for the FOLLOWING grains too, so re-auths ≈
        # #disruptors, NOT #grains — no storm. A genuinely-broken grain still bails on retry.
        if not ran and _pool_reset:
            try:
                lib.pfz_pool_init(2)              # heal the raw g_pool[]
                try:
                    lib.pfz_reopen_smb_fd()       # heal the libsmbclient scratch fd (rmxattr etc.)
                except Exception:
                    pass
                seed = bytes(((i * 131 + 99 * 17 + j * 7) & 0xFF) for j in range(64))
                ret = lib.pfz_grain_run(i, seed, len(seed))
                pcs = _cov()
                best_ret = max(best_ret, ret)
                best_pcs = max(best_pcs, pcs)
                if ret >= 0:
                    ran = True
            except Exception:
                pass
        if best_pcs >= thresh:
            verdict = "WORKS"; works.append((name, best_pcs))
        elif not ran:
            verdict = "BAIL"; bail.append(name)
        else:
            verdict = "DEAD"; dead.append(name)
        bar = "#" * min(40, best_pcs // 8)
        print(f"{_dts()}   [{verdict:5}] {name:30} pcs={best_pcs:6} ret={best_ret:4}  {bar}", flush=True)
    dt = time.time() - t0
    print(f"{_dts()} [selftest] DONE {dt:.1f}s — {len(works)} WORKS / {len(dead)} DEAD / "
          f"{len(bail)} BAIL" + (f" / {len(excl)} EXCL" if excl else "")
          + (f" / {skipped} skipped" if skipped else "") + f"  (of {n})", flush=True)
    if excl:
        print(f"{_dts()}   EXCL (architectural — kept in fleet, unmeasurable here): {sorted(excl)}", flush=True)
    if bail:
        print(f"{_dts()}   BAIL (prereq/setup failed — need pool/auth/fid/config): {sorted(bail)}", flush=True)
    if dead:
        print(f"{_dts()}   DEAD (ran but 0 kernel PCs — remove or fix): {sorted(dead)}", flush=True)
    if works and not dead and not bail:
        print(f"{_dts()}   all grains reached the kernel — fleet is fully meaningful", flush=True)
    # persist the meaningful subset (coverage-desc) for `-t` scoping / campaign curation
    try:
        out = SCRIPT_DIR / 'grain' / 'WORKING_SUBSET.txt'
        out.parent.mkdir(exist_ok=True)
        with open(out, 'w') as f:
            f.write(f"# ksmbdzzer selftest {_dts()} — grains that reached ksmbd kernel code "
                    f"(>= {thresh} PC), coverage desc. {len(works)}/{n - skipped} working.\n")
            f.write("# regenerate: ksmbdzzer.py selftest ; use: "
                    "-t $(grep -v '^#' grain/WORKING_SUBSET.txt)\n")
            for name, pcs in sorted(works, key=lambda x: -x[1]):
                f.write(f"{name}\n")
        print(f"{_dts()} [selftest] wrote {len(works)} working grains → {out}", flush=True)
    except OSError as e:
        print(f"{_dts()} [selftest] could not write WORKING_SUBSET.txt: {e}", flush=True)


def cmd_grain_fuzz(args):
    """Clean 4-PHASE GRAIN orchestrator (the consolidated architecture):
        P1 enumerate grains (the normal-scenario library)
        P2 saturate each grain  — LibFuzzer harness, map-reduce parallel
        P3 combine grains       — compound pairs (concurrent/race = parallel processes)
        P4 save                 — grain corpora + value pool carried to next generation
    Each grain is a "big grain": negotiation+auth+setup are the FIXED valid prefix
    (in harness init), and the fuzzer drives only the LAST target point. No 12-phase
    worker, no random tactics — deep-by-construction grains, directed mutation.

    DURABILITY (DONE): the distilled DB is host-mount durable (ksmbd/.fuzzdb, 9p) so
    a VM wedge costs the in-flight round, not the campaign — g_fb is written there by
    the arbiter, and corpus_save() mirrors CORPUS_DB (corpus+features+value_pool) to
    FUZZDB/corpus.json each P4 (write-through; hot corpus stays in /tmp for speed).
    ARBITER (DONE): DataflowDirector._distill() writes g_fb each round the director
    authenticates → C mutate_i2s() steers next round with no recompile.
    TODO(next-step): MEASURE-FIRST GATE — AUTH is now FIXED (2026-07-04, probe-test
    status=0x00000000, director/oracle live; see [[ksmbdzzer-pool-auth-rootcause]]).
    The remaining precondition is purely a measurement: run ONE oracle-live campaign,
    confirm coverage plateaus at value-gates, THEN roll mutate_i2s out to the raw
    harnesses via GRAIN_I2S_MUTATOR (each raw gen_* needs g_stuck + run_target).
    No longer blocked — deferred only because no campaign is scheduled right now."""
    import sys
    sys.path.insert(0, str(SCRIPT_DIR))
    from grain import (generate_grains, generate_grain_combo_grains,
                        generate_grain_combo_pool, run_grains)
    from itertools import combinations_with_replacement
    rounds = getattr(args, 'round', 1)
    procs = getattr(args, 'procs', None) or _default_procs()
    sat = getattr(args, 'grain_sat', 0.02)
    smax = getattr(args, 'grain_max', 60)

    # Coverage SOURCE — MUST be set before _get_lib() below, because _get_lib() calls
    # pfz_init() which reads KSMBDZZER_KCOV to pick the backend (kcov vs kcov-dataflow).
    # Setting it later left pfz_init opening kcov_dataflow on a kcov-only kernel. Grain
    # workers inherit it via os.environ. (engine_compare/kcov_campagin also export it in
    # the guest env so `init` — a separate process — sees it too.)
    if getattr(args, 'kcov', False):
        os.environ['KSMBDZZER_KCOV'] = '1'
    else:
        os.environ.pop('KSMBDZZER_KCOV', None)

    seed_corpus, global_features, value_pool = corpus_load()   # P4 feed-forward
    vpool = list(value_pool) or [0, 64, 4096, 0x1000, 0xFFFF, 0x40000116]
    lib = _get_lib()
    n = lib.pfz_grain_count()
    grains = [(i, lib.pfz_grain_name(i).decode()) for i in range(n)]
    # Focused testing (-t/--target GRAIN ...): run ONLY the named grains instead of the
    # whole fleet — e.g. `fuzz -t write copychunk` to iterate on specific procedures.
    # Default (no -t) runs everything. Unknown names are warned and ignored.
    _targets = getattr(args, 'target', None)
    if _targets:
        _sel = {t.strip() for t in _targets if t.strip()}
        _known = {nm for (_i, nm) in grains}
        _unknown = _sel - _known
        if _unknown:
            print(f"  [target] WARNING: unknown grain name(s) ignored: {sorted(_unknown)}",
                  flush=True)
        grains = [(i, nm) for (i, nm) in grains if nm in _sel]
        print(f"  [target] focused run — {len(grains)} grain(s): "
              f"{sorted(nm for _i, nm in grains)}", flush=True)
        if not grains:
            print("  [target] no matching grains — nothing to run.", flush=True)
            return
    print(f"ksmbdzzer 4-phase GRAIN fuzzer — {rounds} round(s), {procs} CPUs, {n} grains",
          flush=True)
    # Which coverage/mutator ablation is this run? (set by engine_compare_campagin.sh via
    # KSMBDZZER_ENGINE). Shown in #FFC0CB bold so the active arm is unmistakable in a
    # combined multi-arm log. Re-teal (_LOG_COLOR) after the name so the trailing key stays
    # in this module's colour; the print override appends the final reset.
    _eng = os.environ.get('KSMBDZZER_ENGINE', 'dataflow')
    print(f"  [ENGINE] fuzz coverage/mutator engine = {_PINK_BOLD}{_eng}{_LOG_RESET}{_LOG_COLOR}"
          f"   (dataflow = pc⊕val coverage + i2s · dataflow-vec = whole-arg vector, "
          f"value-class-normalized (pointer/scalar) + i2s · dataflow-rel = dataflow-vec + "
          f"within-record pairwise cmp3 · pc-i2s = pc-only + i2s · pc-havoc = pc-only + havoc)",
          flush=True)
    # Coverage SOURCE banner (KSMBDZZER_KCOV was already set above, before _get_lib(), so
    # pfz_init picked the right backend; the grain workers inherit it via os.environ).
    if os.environ.get('KSMBDZZER_KCOV') == '1':
        print(f"  [COV] coverage source = {_PINK_BOLD}mainline KCOV{_LOG_RESET}{_LOG_COLOR} "
              f"(/sys/kernel/debug/kcov, trace-pc) — kcov-dataflow disabled for this run",
              flush=True)
    # Auth policy → grain env (grains are launched with os.environ). --everytime-auth restores
    # the original per-grain fresh-NTLMv2 pool handshake; default is lazy/session-reuse.
    if getattr(args, 'everytime_auth', False):
        os.environ['KSMBDZZER_EVERYTIME_AUTH'] = '1'
        print("  [auth] --everytime-auth: EVERY grain does a fresh pool NTLMv2 handshake "
              "(heavier ksmbd.mountd load)", flush=True)
    else:
        os.environ.pop('KSMBDZZER_EVERYTIME_AUTH', None)
        print("  [auth] lazy/session-reuse (default): only pool grains authenticate the pool "
              "— avoids the per-grain mountd auth storm", flush=True)
    # In-guest watchdog: recover a USERSPACE stall (hung grain/wave) by killing the
    # stuck grain children in-guest instead of letting the host reboot the VM. Kernel
    # wedges (which starve this thread too) still fall through to the host watchdog.
    _ig_stall = _start_inguest_watchdog()
    print(f"  [in-guest watchdog] armed — unstick a userspace stall after {_ig_stall}s "
          f"(no VM reboot; host watchdog stays the backstop for kernel wedges)", flush=True)
    if value_pool:
        print(f"  [P4 load] carried {len(value_pool)} pool values from prior generation",
              flush=True)
    # P3 combines ALL grains pairwise (r=2, full C(n+1,2) sweep) — no curated
    # COMBO_CORE subset — so interaction bugs are discovered, not presupposed.

    # P1 STABILITY ORACLE state: per-grain baseline ft0 (the bare working scenario's
    # coverage). If a grain that worked before stops working in a later round, the
    # fuzzing destabilized ksmbd → a (non-crashing) bug. Persisted across generations.
    import json
    STAB = Path('/tmp/ksmbdzzer_stability.json')
    try:
        baselines = json.loads(STAB.read_text()) if STAB.exists() else {}
    except Exception:
        baselines = {}
    PCORP = Path('/tmp/ksmbdzzer_corpus_persistent')

    for rnd in range(1, rounds + 1):
        print(f"{_dts()} --- Round {rnd}/{rounds} ---", flush=True)
        # Whole round body in try/except: any UNEXPECTED phase failure (a raise, or a wave
        # the in-guest watchdog had to kill) degrades THIS round instead of aborting the
        # campaign — we log it and fall through to the P4 save + the next round. (Hangs with
        # no timeout can't raise; the watchdog unsticks those so the wait returns here.)
        try:
            _pt = time.time()
            print(f"{_dts()}   [P1 START] round {rnd}: build grain harnesses ({n} lib grains + raw)", flush=True)
            ggrains = generate_grains(grains, vpool)
            # The PROVEN raw-PDU grains: common.h harnesses that establish the working
            # guest-auth prefix (smb_setup + CREATE) and fuzz the RAW target PDU — your
            # principle, already implemented (create_ctx reaches ~ft3900). These reach
            # deep on parse-rich commands; the lib grains fuzz semantic params.
            try:
                from grain import generate_all_grains, generate_v2_grains
                raw_grains = generate_all_grains(vpool)
                ggrains += raw_grains
                # The CLEAN v2 hybrid grains: KCOV path coverage for the bulk, trace-args/
                # ret directed mutation ONLY when stuck (all in the C harness). These are
                # the proving-case grains vs the random-havoc raw grains above.
                v2 = generate_v2_grains()
                ggrains += v2
                print(f"  [P1 grain] +{len(raw_grains)} raw-PDU grains + {len(v2)} v2 "
                      f"hybrid grains (KCOV + trace-args/ret-at-stuck)", flush=True)
            except Exception as e:
                print(f"  [P1] raw-grain gen error: {e!r}", flush=True)
            print(f"{_dts()}   [P1 END] {len(ggrains)} harnesses built in {time.time()-_pt:.0f}s", flush=True)
            _pt = time.time()
            print(f"{_dts()}   [P2 START] saturate {len(ggrains)} grain harnesses, {procs}-way "
                  f"(per-grain LibFuzzer + trace-args/ret directed mutation)", flush=True)
            p2_stats = {}
            crashes = run_grains(ggrains, sat_ratio=sat, max_time=smax, parallelism=procs,
                                  out_stats=p2_stats)
            _p2prod = sum(1 for s in p2_stats.values() if s.get('productive'))
            print(f"{_dts()}   [P2 END] {time.time()-_pt:.0f}s — {_p2prod}/{len(p2_stats)} grains productive"
                  f"{f', {len(crashes)} CRASH' if crashes else ''}", flush=True)
            if crashes:
                print(f"  !!! CRASH in P2: {crashes}", flush=True)
                corpus_save(seed_corpus, global_features, vpool)
                return

            # ── P1 STABILITY ORACLE: did any working grain STOP working this round? ──
            # Re-running the bare grain each round is a canary: a normal scenario that
            # reached deep before but now collapses means the prior round's fuzzing
            # destabilized ksmbd's state — a real (non-crashing) bug. ft0 is exactly the
            # bare-grain coverage, so we just compare it to the grain's known baseline.
            for nm, s in p2_stats.items():
                g = nm.replace('grain_', ''); cur = s.get('ft0', 0); base = baselines.get(g)
                if base is None:
                    if cur >= 100:
                        baselines[g] = cur            # first solid observation = baseline
                elif base >= 100 and cur < 0.5 * base:
                    hist = PCORP / g
                    nfiles = len(list(hist.iterdir())) if hist.is_dir() else 0
                    print(f"  [!!! STABILITY] grain '{g}': baseline ft0={base} → now {cur} "
                          f"— the NORMAL scenario STOPPED WORKING → ksmbd may be "
                          f"DESTABILIZED (non-crashing state-corruption bug). Narrow with "
                          f"its {nfiles}-input historic corpus at {hist}", flush=True)
                else:
                    baselines[g] = max(base, cur)     # ratchet the baseline up
            try: STAB.write_text(json.dumps(baselines))
            except Exception: pass

            # ── DATAFLOW CONTRACT ORACLE (a check, not a phase) ──────────────────────
            # The differentiating oracle: probe write-side access control via kcov-
            # dataflow (e.g. ksmbd honoring WRITE/DELETE/LOCK on a handle whose granted
            # access lacks that right — the non-crashing LPE class syzkaller is blind to).
            # Run once per round on the shared lib AFTER P2, so it also acts as a
            # contract-stability canary: a violation that appears only after fuzzing
            # means the mutation corrupted server state. Safe no-op if the probe can't
            # authenticate to [privtest]; any violation is written to FINDINGS_DIR.
            try:
                _before = len(list(FINDINGS_DIR.glob('*.json'))) if FINDINGS_DIR.exists() else 0
                run_dataflow_director(lib, _WORKER_OCTET)
                _after = len(list(FINDINGS_DIR.glob('*.json'))) if FINDINGS_DIR.exists() else 0
                if _after > _before:
                    print(f"  [!!! ORACLE] write-side contract VIOLATION — {_after-_before} new "
                          f"reproducer(s) in {FINDINGS_DIR}", flush=True)
                else:
                    print(f"  [oracle] write-side contract check passed (no violation)", flush=True)
            except Exception as _oe:
                print(f"  [oracle] skipped: {_oe!r}", flush=True)

            # Corpus growth report: each round must accumulate MORE coverage-beating
            # inputs than the last. The real corpora are PCORP/grain_<name> (libFuzzer's
            # own corpus dirs, persisted across rounds = the feed-forward).
            total_corpus = sum(len([f for f in d.iterdir() if f.is_file()])
                               for d in PCORP.iterdir() if d.is_dir()) if PCORP.is_dir() else 0
            print(f"  [corpus] {total_corpus} accumulated coverage-beating inputs "
                  f"(persisted → next round replays them)", flush=True)
            # FEED-FORWARD check: a grain's ft0 (its FIRST ft = the loaded corpus's
            # coverage) should JUMP across rounds, because round N replays round N-1's
            # corpus. Track per-grain ft0 to prove round 1 feeds round 2.
            ff = getattr(cmd_grain_fuzz, '_prev_ft0', {})
            gained = [(nm.replace('grain_', ''), ff.get(nm, 0), s.get('ft0', 0))
                      for nm, s in p2_stats.items() if s.get('ft0', 0) > ff.get(nm, 0) + 50]
            if rnd > 1 and gained:
                print(f"  [feed-forward] {len(gained)} grains START deeper this round "
                      f"(corpus carried): " +
                      ", ".join(f"{g}:{a}→{b}" for g, a, b in sorted(gained, key=lambda x: -x[2])[:6]),
                      flush=True)
            cmd_grain_fuzz._prev_ft0 = {nm: s.get('ft0', 0) for nm, s in p2_stats.items()}

            # ── P3 COMBINATION: FULL all-pairs sweep (r=2 over EVERY grain) ──────────
            # Design change: combine ALL grains pairwise with replacement — C(n+1,2)
            # pairs (95 grains → 4,560) — NOT a curated COMBO_CORE subset. The point of
            # combination is to DISCOVER interaction bugs, so we don't presuppose which
            # grains matter; every pair is a candidate. This is tractable because the
            # pool is ONE compiled generic harness + a per-pair symlink (grain_gc_a_b),
            # and run_grains schedules all 4,560 through the `-procs`-bounded execution
            # pool (max `procs` concurrent), so the phase is run-bound, not compile-bound.
            pairs = [(a, na, b, nb)
                     for (a, na), (b, nb) in combinations_with_replacement(grains, 2)]
            # P3 is the expensive tail (4,560 runs). It is a REFINEMENT, not a feed-
            # forward step, so run it ONLY on the final round — intermediate rounds stay
            # a fast P1→P2→P4 loop so round N actually feeds round N+1.
            if pairs and rnd != rounds:
                print(f"{_dts()}   [P3 skip] {len(pairs)} all-pairs combos deferred to final "
                      f"round (intermediate rounds stay fast so feed-forward reaches round "
                      f"{rnd+1})", flush=True)
                pairs = []
            # Optional P3 budget. KSMBDZZER_P3_MAX_COMBOS caps the all-pairs sweep so a
            # TIME-BOXED run (the engine-comparison campaign) finishes P3 and powers off
            # cleanly instead of tripping the VM hard-cap mid-sweep — the failure mode where
            # PREP alone (one harness compiled per pair) burns ~20 min and the sweep never
            # completes. 0 = skip P3 entirely; N>0 = run only the first N pairs; unset =
            # full C(n+1,2). Capping bounds PREP too (harness count == pair count). P3 is a
            # crash-yield refinement and contributes nothing to the coverage comparison, so
            # the comparison arms default it to 0.
            _p3cap = os.environ.get('KSMBDZZER_P3_MAX_COMBOS')
            if pairs and _p3cap is not None and _p3cap.isdigit() and int(_p3cap) < len(pairs):
                _cap = int(_p3cap)
                print(f"{_dts()}   [P3 cap] KSMBDZZER_P3_MAX_COMBOS={_cap}: "
                      f"{'SKIP P3' if _cap == 0 else f'sampling {_cap}/{len(pairs)} combos'} "
                      f"(budget-bounded so the VM powers off before the hard-cap)", flush=True)
                pairs = pairs[:_cap]
            if pairs:
                _pt = time.time()
                _cf0 = len(list(FINDINGS_DIR.glob('*.json'))) if FINDINGS_DIR.exists() else 0
                # generate_grain_combo_pool() is a SILENT stretch (1 compile of the generic
                # combo harness + up to C(n+1,2) symlinks + dict writes) that used to print
                # nothing until [P3 START] — a run killed here looked wedged. Bracket it so the
                # phase is visible while it builds.
                print(f"{_dts()}   [P3 PREP] building {len(pairs)} all-pairs combo harnesses "
                      f"(1 compile + symlink pool)…", flush=True)
                cgrains = generate_grain_combo_pool(pairs, vpool)   # 1 compile + symlinks
                print(f"{_dts()}   [P3 PREP END] {time.time()-_pt:.0f}s — {len(cgrains)} combo "
                      f"harnesses ready; starting the execution sweep", flush=True)
                print(f"{_dts()}   [P3 START] combination phase: {len(cgrains)}/{len(pairs)} "
                      f"all-pairs grain combos (C({n}+1,2), r=2 over every grain), {procs}-way "
                      f"execution pool — the highest crash/finding-yield phase", flush=True)
                _ccrash = run_grains(cgrains, sat_ratio=sat, max_time=smax, parallelism=procs)
                _cf1 = len(list(FINDINGS_DIR.glob('*.json'))) if FINDINGS_DIR.exists() else 0
                print(f"{_dts()}   [P3 END] {time.time()-_pt:.0f}s — {len(cgrains)} combos run, "
                      f"{_cf1-_cf0} new finding(s)"
                      f"{f', {len(_ccrash)} CRASH' if _ccrash else ''}", flush=True)
                if _ccrash:
                    print(f"{_dts()}   !!! CRASH in P3 combine: {_ccrash}", flush=True)
            else:
                print(f"{_dts()}   [P3 END] no combination this round (deferred to final round)", flush=True)
        except Exception as _round_err:
            import traceback
            print(f"{_dts()}   [!!! ROUND {rnd} FAILED] {_round_err!r} — degrading this round; "
                  f"saving the corpus and continuing to the next round", flush=True)
            traceback.print_exc()
        # P4 ALWAYS runs — even after a failed/aborted round — so the accumulated corpus +
        # value pool survive and feed the next generation (crash-resilient continuity).
        try:
            _pt = time.time()
            print(f"{_dts()}   [P4 START] persist grain corpora + value pool (feed-forward to next round)",
                  flush=True)
            corpus_save(seed_corpus, global_features, list(vpool))   # P4
            print(f"{_dts()}   [P4 END] {time.time()-_pt:.1f}s — corpora + pool carried → next generation "
                  f"deeper", flush=True)
        except Exception as _p4e:
            print(f"{_dts()}   [P4] corpus save failed: {_p4e!r}", flush=True)
    print("=== 4-phase grain campaign done ===", flush=True)
    # Force immediate exit. After the campaign, lingering daemons (ksmbd.mountd, the KDC)
    # and the daemon watchdog thread keep the process/serial pipe open, so a plain return
    # leaves fuzz "done" but not exited — vng never sees the --exec command finish and the
    # host STALL watchdog burns 420s per arm before killing the idle VM. os._exit(0) skips
    # atexit/thread-join and terminates now; all output is already flushed, and the shell's
    # trailing `poweroff -f` then powers the guest off cleanly.
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)


def _default_procs():
    """Default parallelism = the machine's usable CPU count (cgroup/taskset-aware),
    so every phase (grain saturation, combination) utilizes all cores by default."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except Exception:
        return os.cpu_count() or 4


def main():
    parser = argparse.ArgumentParser(
        prog='ksmbdzzer.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'ksmbdzzer — kcov-dataflow-guided, SMB-procedure "grain" fuzzer for the\n'
            'Linux in-kernel SMB server (ksmbd). Authorized DEFENSIVE hardening only.\n'
            '\n'
            'Each grain is a deep-by-construction harness: a FIXED valid prefix\n'
            '(negotiate + NTLMv2 auth + tree-connect + open a real fid) with only the\n'
            'LAST SMB2/SMB3 endpoint fuzzed, so mutation lands on real server state\n'
            'instead of the parser front door. Round-based, not time-based.'),
        epilog=(
            'typical workflow (run inside the virtme-ng guest):\n'
            '  ksmbdzzer.py init                        # bring up ksmbd + share + RDMA + KDC\n'
            '  ksmbdzzer.py fuzz -r 5 --grain-max 25 # 5 rounds over the whole grain fleet\n'
            '  ksmbdzzer.py fuzz -r 5 -t write copychunk reparse   # focus a few grains\n'
            '  ksmbdzzer.py probe-test                  # one-shot write-side oracle check\n'
            '\n'
            "run 'ksmbdzzer.py <command> -h' for per-command options.\n"
            'the engine comparison (dataflow vs pc-only) is driven by '
            '~/engine_compare_campagin.sh.'),
    )
    sub = parser.add_subparsers(dest='cmd', metavar='<command>')

    ip = sub.add_parser(
        'init', help='Set up the target: ksmbd + share + Soft-RDMA + KDC',
        description=(
            'Prepare the in-guest target before fuzzing: create the share/mount dirs,\n'
            'load the ksmbd module, provision the fuzz:fuzz SMB user, bring up Software\n'
            'RDMA (SIW/RXE) for SMBDirect, (re)start ksmbd.mountd, mount //127.0.0.1/share,\n'
            'and start an optional KDC for the Kerberos path. Each step logs [init] N/9 so a\n'
            'stall is attributable. Safe to re-run (idempotent). Run this ONCE per boot\n'
            'before fuzz.'))
    ip.add_argument('--install-deps', action='store_true',
                    help='apt-get install the runtime deps first (ksmbd-tools, cifs-utils, '
                         'smbclient, krb5, rdma-core). Usually already present in the image.')

    vp = sub.add_parser('validate', help='Quick liveness/sanity check of the target')
    vp.add_argument('-time', type=int, default=10, help='Seconds to probe (default: 10).')

    sub.add_parser('probe-test', help='Run the dataflow director once and exit (fast oracle check)')

    gp = sub.add_parser(
        'fuzz',
        help='Run the fuzzer: 4-phase round-based GRAIN campaign',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Round-based GRAIN fuzzer (this is THE fuzzing command).\n'
            'Each round runs 4 phases:\n'
            '  P1 enumerate — build one libFuzzer harness per grain (the normal-scenario library)\n'
            '  P2 saturate  — fuzz each grain to coverage plateau, kcov-dataflow-directed, N-way\n'
            '  P3 combine   — all-pairs compound of grains (interaction bugs) on the final round\n'
            '  P4 save      — carry the strong grains + value pool forward to the next round\n'
            'Rounds are generational: round N replays round N-1\'s corpus (feed-forward). The\n'
            'corpus is mirrored to the host-durable .fuzzdb so a VM wedge costs a round, not the\n'
            'campaign. NOTE: this is round-based — there is no time budget; use -r for depth.'),
        epilog=(
            'examples:\n'
            '  ksmbdzzer.py fuzz -r 5 --grain-max 25          # whole fleet, 5 rounds\n'
            '  ksmbdzzer.py fuzz -r 3 -t write copychunk        # only the write + copychunk grains\n'
            '  ksmbdzzer.py fuzz -r 1 --kcov --verbose          # mainline KCOV coverage source\n'
            '\n'
            'a "grain" is one SMB2/SMB3 procedure harness; -t/--target restricts the run to a\n'
            'subset for focused testing (default: all grains in libksmbdzzer.so).'))
    gp.add_argument('-r', '--round', dest='round', type=int, default=1, metavar='N',
                    help='Number of generations to run; each carries the strong grains forward '
                         '(default: 1). This is the depth knob (round-based, not time-based).')
    gp.add_argument('-procs', type=int, default=_default_procs(), metavar='N',
                    help='Parallel grain workers (default: all CPUs). P3 combination needs >= 2.')
    gp.add_argument('--everytime-auth', dest='everytime_auth', action='store_true',
                    help='Make EVERY grain do a fresh pool NTLMv2 handshake up front (original '
                         'behaviour). Default is lazy/session-reuse: only pool-based grains '
                         'authenticate the pool, avoiding the per-grain mountd-IPC auth storm '
                         'that 0-execs the fleet under -procs>1.')
    gp.add_argument('--grain-sat', dest='grain_sat', type=float, default=0.02, metavar='R',
                    help='Per-grain coverage-saturation ratio: stop a grain when new-feature '
                         'growth drops below R for a few windows (default: 0.02).')
    gp.add_argument('--grain-max', dest='grain_max', type=int, default=60, metavar='S',
                    help='Hard ceiling (seconds) per grain grain if it never saturates '
                         '(default: 60). Lower = broader/shallower rounds.')
    gp.add_argument('-t', '--target', dest='target', nargs='+', metavar='GRAIN', default=None,
                    help='Run ONLY these grains (space-separated names, e.g. '
                         '-t write copychunk reparse). Default: the whole fleet. '
                         'For focused/targeted testing of specific procedures.')
    gp.add_argument('--verbose', action='store_true',
                    help='Extra per-grain diagnostics (i2s hits, kernel-PC counts).')
    gp.add_argument('--kcov', dest='kcov', action='store_true',
                    help='Use mainline /sys/kernel/debug/kcov (trace-pc) as the coverage source '
                         'instead of kcov-dataflow — the fork-free baseline for the KCOV vs '
                         'KCOV-DATAFLOW comparison. Sets KSMBDZZER_KCOV=1 for the grain workers.')

    stp = sub.add_parser(
        'selftest',
        help=('Pre-P2 grain-VALIDITY check: run each grain a few times and verify it '
              'reaches ksmbd KERNEL code (produces coverage). Cheap fleet-wide filter '
              'for "which grains are meaningful" — WORKS/DEAD/BAIL per grain + writes '
              'grain/WORKING_SUBSET.txt. Needs `init` first + a non-blind kernel.'),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  ksmbdzzer.py init && ksmbdzzer.py selftest        # validate the whole fleet\n'
                '  ksmbdzzer.py selftest --repeats 5 --min-pcs 3      # stricter\n'
                '  ksmbdzzer.py selftest -t write copychunk lock_array # a subset\n'))
    stp.add_argument('--repeats', type=int, default=3, metavar='N',
                     help='Runs per grain; MAX kernel-PC count is taken (default 3). More = '
                          'lets pool-bootstrap/ramp settle, fewer false DEADs.')
    stp.add_argument('--min-pcs', dest='min_pcs', type=int, default=1, metavar='N',
                     help='Min kernel PCs to count a grain as WORKS (default 1 = reached ksmbd '
                          'at all). Raise to filter shallow reject-path grains.')
    stp.add_argument('-t', '--target', dest='target', nargs='+', metavar='GRAIN', default=None,
                     help='Only check these grains (default: whole fleet).')

    bg = sub.add_parser(
        'build-grains',
        help=('HOST-side pre-build of the whole grain fleet so the in-guest P1 hits '
              'the compile cache and skips clang (turns the 11–20 min 9p rebuild into '
              'seconds). Grains are deterministic, so this is safe to reuse every run.'))
    bg.add_argument('--dynamic', action='store_true',
                    help=('Link -lksmbdzzer with an rpath to libksmbdzzer.so (default is '
                          'STATIC-embed: libksmbdzzer.c compiled into each grain, no '
                          '.so runtime dependency — more robust over 9p).'))

    args = parser.parse_args()
    if args.cmd == 'init': cmd_init(install_deps=args.install_deps)
    elif args.cmd == 'fuzz': cmd_grain_fuzz(args)
    elif args.cmd == 'selftest': cmd_selftest(args)
    elif args.cmd == 'validate': cmd_validate(args)
    elif args.cmd == 'probe-test': cmd_probe_test()
    elif args.cmd == 'build-grains': cmd_build_grains(args)
    else: parser.print_help()


def cmd_build_grains(args):
    """HOST-side pre-build of the grain fleet (P1 offload).

    Grains are deterministic — the per-round value_pool goes into the .dict, not the
    C source, so identical source ⇒ identical binary. Building the fleet here on the
    native FS (seconds) lets the in-guest P1 hit the byte-identical-source compile
    cache and SKIP clang, instead of recompiling ~34 harnesses over the slow 9p mount
    (~11–20 min — the biggest driver of timeout-flakiness). If a binary is missing or
    stale in-guest, P1 still falls back and compiles it (the existing _compile path),
    so this is a pure speedup, never a hard dependency.

    Default build is STATIC-embed (libksmbdzzer.c compiled into each grain; no
    libksmbdzzer.so runtime dep — robust over 9p). --dynamic keeps the -lksmbdzzer link.
    Full `-static` is impossible: libsmbclient ships only as a .so, so it stays dynamic."""
    import sys, glob, time as _t
    sys.path.insert(0, str(SCRIPT_DIR))
    os.environ['KSMBDZZER_FORCE_BUILD'] = '1'   # explicit rebuild: bypass the compile cache
    if getattr(args, 'dynamic', False):
        os.environ.pop('KSMBDZZER_STATIC', None)
        print("  [build-grains] DYNAMIC build (-lksmbdzzer, rpath to libksmbdzzer.so)",
              flush=True)
    else:
        os.environ['KSMBDZZER_STATIC'] = '1'
        print("  [build-grains] STATIC-embed build (libksmbdzzer.c compiled into each "
              "grain; only system .so remain dynamic — robust over 9p)", flush=True)
    lib = _get_lib(init=False)   # registry-only: build-grains just compiles (no coverage/SMB)
    if lib is None:
        print("  [build-grains] libksmbdzzer.so failed to load — build the .so first "
              "(cc -shared ... libksmbdzzer.c). Aborting.", flush=True)
        return
    n = lib.pfz_grain_count()
    grains = [(i, lib.pfz_grain_name(i).decode()) for i in range(n)]
    vpool = [0, 64, 4096, 0x1000, 0xFFFF, 0x40000116]   # binary-independent (→ .dict only)
    from grain import generate_grains, generate_all_grains, generate_v2_grains
    from grain.gen import GRAIN_DIR
    t0 = _t.time(); total = 0
    for label, fn in (('lib', lambda: generate_grains(grains, vpool)),
                      ('raw', lambda: generate_all_grains(vpool)),
                      ('v2',  lambda: generate_v2_grains())):
        try:
            got = [x for x in (fn() or []) if x and x[0]]
            total += len(got)
            print(f"  [build-grains] {label}: {len(got)} harness(es)", flush=True)
        except Exception as e:
            print(f"  [build-grains] {label} FAILED: {e!r}", flush=True)
    bins = [p for p in glob.glob(str(GRAIN_DIR / 'grain_*'))
            if not p.endswith('.c') and not p.endswith('.dict')]
    print(f"  [build-grains] done in {_t.time()-t0:.0f}s — {total} built this run, "
          f"{len(bins)} grain binaries now in {GRAIN_DIR}", flush=True)


def cmd_probe_test():
    """Fast standalone check: bring up the worker lib, run the director once,
    print the outcome and any reproducers. Used to validate the oracle without a
    full fuzz campaign. Assumes `ksmbdzzer.py init` already configured ksmbd."""
    print("=== probe-test: authenticate + run write-side contract oracle ===", flush=True)
    lib = _get_lib()
    if lib is None:
        print("  [probe-test] lib init failed", flush=True); return
    ok = run_dataflow_director(lib, _WORKER_OCTET)
    print(f"  [probe-test] director ran: {'ok' if ok else 'NO-OP (see above)'}", flush=True)
    if FINDINGS_DIR.exists():
        found = sorted(FINDINGS_DIR.glob('*.json'))
        print(f"  [probe-test] {len(found)} reproducer(s) in {FINDINGS_DIR}", flush=True)
        for f in found:
            print(f"      {f.name}", flush=True)
    else:
        print(f"  [probe-test] no findings dir ({FINDINGS_DIR})", flush=True)

if __name__ == '__main__':
    main()

# ─── Merged: smb_proto (raw TCP SMB2 client) ────────────────────────────────
"""
smb_proto.py — Raw TCP SMB2 protocol engine with stateful grammar.

Provides true parallel raw socket connections (no smbprotocol serialization).
Defines valid SMB state transitions for deep stateful fuzzing.

State machine:
  NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE → [ops] → CLOSE → TREE_DISCONNECT
"""
import socket, struct, os, random, hashlib, threading

# SMB2 commands
CMD_NEGOTIATE = 0x0000
CMD_SESSION_SETUP = 0x0001
CMD_LOGOFF = 0x0002
CMD_TREE_CONNECT = 0x0003
CMD_TREE_DISCONNECT = 0x0004
CMD_CREATE = 0x0005
CMD_CLOSE = 0x0006
CMD_FLUSH = 0x0007
CMD_READ = 0x0008
CMD_WRITE = 0x0009
CMD_LOCK = 0x000A
CMD_IOCTL = 0x000B
CMD_CANCEL = 0x000C
CMD_QUERY_DIRECTORY = 0x000E
CMD_CHANGE_NOTIFY = 0x000F
CMD_QUERY_INFO = 0x0010
CMD_SET_INFO = 0x0011
CMD_OPLOCK_BREAK = 0x0012


# ─── Stateful Grammar: Valid SMB State Transitions ────────────────────────────

# Valid operations per state
STATE_OPS = {
    'FILE_OPEN': [CMD_WRITE, CMD_READ, CMD_LOCK, CMD_IOCTL, CMD_QUERY_INFO,
                  CMD_SET_INFO, CMD_FLUSH, CMD_CLOSE, CMD_QUERY_DIRECTORY],
    'TREE': [CMD_CREATE, CMD_TREE_DISCONNECT],
    'SESSION': [CMD_TREE_CONNECT, CMD_LOGOFF],
}


# ─── Merged: sharp (boundary search + anomaly + trust boundary) ─────────────
"""
sharp.py — Sharp analysis for write-side LPE hunting.

1. Binary search boundaries: find exact ret 0→error transition per field
2. Two-socket race: socket A writes, socket B disconnects mid-write
3. Anomaly detection: flag ret=0 for values > 2× previously-seen max
4. Stateful sequence learning: track deepest PCs, replay with mutations
"""
import struct, os, socket, threading, time
from pathlib import Path


# ─── 1. Binary Search Boundaries ─────────────────────────────────────────────


# ─── 2. Two-Socket Race ──────────────────────────────────────────────────────


# ─── 3. Anomaly Detection ────────────────────────────────────────────────────


# ─── 4. Stateful Sequence Learning ───────────────────────────────────────────


# ─── Public API ───────────────────────────────────────────────────────────────

# Persistent state across rounds


# ─── 5. Logic Bug Detection (Trust Boundary Analysis) ─────────────────────────


# ─── 6. Active Data-Flow Guided Mutation Engine ──────────────────────────────


# ─── 7. Compound Chain Request Generator ─────────────────────────────────────


# ─── 8. Cross-Session File ID Replay Attack ───────────────────────────────────


# ─── 9. CHANGE_NOTIFY Async Cancel Fuzzer ─────────────────────────────────────


# ─── 10. Durable Handle V2 Reconnect Fuzzer ──────────────────────────────────


