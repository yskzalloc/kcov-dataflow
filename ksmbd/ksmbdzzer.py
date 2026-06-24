#!/usr/bin/env python3
"""
ksmbdzzer.py — KSMBD write-side LPE fuzzer.

Usage:
  ksmbdzzer.py init [--install-deps]
  ksmbdzzer.py fuzz -t 5h -procs 2 -target write -sniper-time 30
  ksmbdzzer.py validate -time 10
  ksmbdzzer.py campaign -hours 5
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import multiprocessing
import os
import random
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

SCRIPT_DIR = Path(__file__).parent


# ─── Configuration (dataclass) ────────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    """Immutable fuzzer configuration."""
    conf_file: Path = field(default_factory=lambda: SCRIPT_DIR / 'ksmbd-sandbox.config')
    corpus_db: Path = Path('/tmp/ksmbdzzer_corpus.json')
    mount: str = '/home/debian-sid/mnt'
    share: str = '/tmp/ksmbd_share'
    pwdb: str = '/tmp/ksmbd_conf/ksmbdpwd.db'
    buf_words: int = 1 << 16
    kcov_df_init: int = 0x80086401
    kcov_df_remote_enable: int = 0x00006466
    kcov_df_remote_disable: int = 0x00006467


CFG = Config()


@dataclass
class RoundResult:
    """Result from a single worker cycle."""
    features: int = 0
    transitions: int = 0
    raw_pdus: int = 0
    bugs: int = 0
    corpus: list = field(default_factory=list)
    new_features: list = field(default_factory=list)
    new_values: list = field(default_factory=list)


# Legacy aliases (used throughout — will remove in full refactoring)
CONF_FILE = CFG.conf_file
CORPUS_DB = CFG.corpus_db
MOUNT = CFG.mount
SHARE = CFG.share
PWDB = CFG.pwdb
KCOV_DF_INIT = CFG.kcov_df_init
KCOV_DF_REMOTE_ENABLE = CFG.kcov_df_remote_enable
KCOV_DF_REMOTE_DISABLE = CFG.kcov_df_remote_disable
BUF_WORDS = CFG.buf_words

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.mmap.restype = ctypes.c_void_p


# ─── VFS Operations (Strategy Pattern: first-class functions) ─────────────────

VfsOp = Callable[[str, int, bytes], None]


# ─── Service Layer (Composition) ──────────────────────────────────────────────

@dataclass
class KsmbdService:
    """Manages ksmbd lifecycle: init, mount, recovery."""
    cfg: Config = field(default_factory=lambda: CFG)

    def restart_and_remount(self) -> bool:
        """Full restart: kill mountd, reload module if needed, remount."""
        subprocess.run(f'umount -l {self.cfg.mount}'.split(), capture_output=True)
        subprocess.run(f'umount -l {self.cfg.mount}_acl'.split(), capture_output=True)
        time.sleep(1)
        if subprocess.run('ls /sys/module/ksmbd'.split(), capture_output=True).returncode != 0:
            subprocess.run('modprobe ksmbd'.split(), capture_output=True)
            time.sleep(1)
        subprocess.run('pkill -9 ksmbd.mountd'.split(), capture_output=True)
        time.sleep(0.5)
        subprocess.Popen(f'ksmbd.mountd -C {self.cfg.conf_file} -P {self.cfg.pwdb} -n'.split(),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.run(
            f'mount -t cifs //127.0.0.1/share {self.cfg.mount} -o username=fuzz,password=fuzz,vers=3.0,cache=none,noperm'.split(),
            capture_output=True)
        try:
            Path(f'{self.cfg.mount}/fuzz_target').write_bytes(b'x')
            return True
        except:
            return False


_service = KsmbdService()


# ─── Corpus DB ────────────────────────────────────────────────────────────────

def corpus_load():
    """Load persistent corpus from JSON db."""
    if not CORPUS_DB.exists():
        return [], set(), []
    try:
        raw = json.loads(CORPUS_DB.read_text())
        entries = [(e['offset'], bytes.fromhex(e['data']), e['rank']) for e in raw['corpus']]
        return entries, set(raw.get('features', [])), raw.get('value_pool', [])
    except Exception:
        return [], set(), []

def corpus_save(corpus, features, value_pool):
    """Save corpus to JSON db."""
    data = {
        'corpus': [{'offset': c[0], 'data': c[1] if isinstance(c[1], str) else c[1].hex(), 'rank': c[2]} for c in corpus[:512]],
        'features': list(features)[:50000],
        'value_pool': value_pool[:4096],
    }
    CORPUS_DB.write_text(json.dumps(data))

# ─── Init ─────────────────────────────────────────────────────────────────────

def cmd_init(install_deps=False):
    if install_deps:
        print('[*] Installing dependencies...')
        subprocess.run('apt-get update -qq && apt-get install -y -qq krb5-kdc krb5-admin-server smbclient'.split(),
                      capture_output=True)
        print('[+] Dependencies installed')
    os.makedirs(SHARE, exist_ok=True)
    os.makedirs('/tmp/ksmbd_acl', exist_ok=True)
    os.makedirs('/tmp/ksmbd_priv', exist_ok=True)
    os.makedirs('/tmp/ksmbd_conf', exist_ok=True)
    os.makedirs(MOUNT, exist_ok=True)
    os.makedirs(f'{MOUNT}_acl', exist_ok=True)
    os.chmod(SHARE, 0o777)
    os.chmod('/tmp/ksmbd_acl', 0o755)
    os.chmod('/tmp/ksmbd_priv', 0o777)
    subprocess.run(f'ksmbd.adduser -C {CONF_FILE} -P {PWDB} -a fuzz -p fuzz'.split(), capture_output=True)
    subprocess.Popen(f'ksmbd.mountd -C {CONF_FILE} -P {PWDB} -n'.split(),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    r = subprocess.run(f'mount -t cifs //127.0.0.1/share {MOUNT} -o username=fuzz,password=fuzz,vers=3.1.1,cache=none,noperm'.split(), capture_output=True)
    if r.returncode != 0:
        subprocess.run(f'mount -t cifs //127.0.0.1/share {MOUNT} -o username=fuzz,password=fuzz,vers=3.0,cache=none,noperm'.split(), check=True, capture_output=True)
    Path(f'{MOUNT}/fuzz_target').write_bytes(b'x')
    # Mount ACL share (exercises smbacl.c — non-root permission checks)
    r2 = subprocess.run(f'mount -t cifs //127.0.0.1/aclshare {MOUNT}_acl -o username=fuzz,password=fuzz,vers=3.0,cache=none'.split(), capture_output=True)
    if r2.returncode == 0:
        try: Path(f'{MOUNT}_acl/fuzz_acl').write_bytes(b'x')
        except: pass
        print(f'[+] ACL share: {MOUNT}_acl')

    # NDR/DCE-RPC: Access IPC$ share (exercises ndr.c via srvsvc/wkssvc)
    try:
        subprocess.run(f'smbclient //127.0.0.1/ipc$ -U fuzz%fuzz -c "help" -m SMB3'.split(),
                      capture_output=True, timeout=5)
        print('[+] NDR/IPC$ exercised')
    except: pass

    # KDC setup: start krb5kdc with minimal config for Kerberos auth path
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
        os.environ['KRB5_CONFIG'] = str(krb5_conf)
        os.environ['KRB5_KDC_PROFILE'] = str(kdc_conf)
        # Create KDC database
        if not (kdc_dir / 'principal').exists():
            subprocess.run(
                f'kdb5_util create -s -r FUZZ.LOCAL -P fuzzpass'.split(),
                capture_output=True, timeout=10,
                env={**os.environ, 'KRB5_CONFIG': str(krb5_conf), 'KRB5_KDC_PROFILE': str(kdc_conf)})
            # Add principals
            for princ in ['fuzz', 'cifs/127.0.0.1']:
                subprocess.run(
                    f'kadmin.local -q addprinc -pw fuzz {princ}@FUZZ.LOCAL'.split(),
                    capture_output=True, timeout=5,
                    env={**os.environ, 'KRB5_CONFIG': str(krb5_conf), 'KRB5_KDC_PROFILE': str(kdc_conf)})
        # Start KDC
        subprocess.Popen(
            ['krb5kdc', '-n'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, 'KRB5_CONFIG': str(krb5_conf), 'KRB5_KDC_PROFILE': str(kdc_conf)})
        time.sleep(0.5)
        print('[+] KDC running (FUZZ.LOCAL, port 88)')
    except Exception:
        # krb5 not installed — just set config for future use
        try:
            krb5_conf = Path('/tmp/krb5.conf')
            if not krb5_conf.exists():
                krb5_conf.write_text('[libdefaults]\ndefault_realm = FUZZ.LOCAL\n'
                                     '[realms]\nFUZZ.LOCAL = { kdc = 127.0.0.1 }\n')
                os.environ['KRB5_CONFIG'] = str(krb5_conf)
        except: pass
        print('[+] KRB5 config written (kdc not available)')

    print(f'[+] KSMBD ready: {MOUNT}')

# ─── DfRemote (implements DataflowCapture protocol) ───────────────────────────

class DataflowCapture:
    """Protocol: any object providing these methods satisfies the interface."""
    def enable(self) -> None: ...
    def disable(self) -> None: ...
    def features_fast(self) -> set[int]: ...
    def count_success_returns(self) -> tuple[int, int, set]: ...
    def read(self) -> tuple[list[int], list[tuple[int, int]]]: ...


class DfRemote:
    def __init__(self):
        self.fd = os.open('/sys/kernel/debug/kcov_dataflow', os.O_RDWR)
        assert libc.ioctl(self.fd, KCOV_DF_INIT, ctypes.c_ulong(BUF_WORDS)) == 0
        ptr = libc.mmap(None, BUF_WORDS * 8, 0x3, 0x01, self.fd, 0)
        assert ptr != ctypes.c_void_p(-1).value
        self.buf = (ctypes.c_uint64 * BUF_WORDS).from_address(ptr)

    def enable(self):
        self.buf[0] = 0
        libc.ioctl(self.fd, KCOV_DF_REMOTE_ENABLE, 0)

    def disable(self):
        libc.ioctl(self.fd, KCOV_DF_REMOTE_DISABLE, 0)

    def features_fast(self):
        h = _load_harness()
        if h:
            if not hasattr(h, '_ps'):
                h.harness_parse_df.restype = ctypes.c_int
                h.harness_parse_df.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.c_int]
                h._ps = True
            out = (ctypes.c_uint * 4096)()
            n = h.harness_parse_df(ctypes.addressof(self.buf), BUF_WORDS, out, 4096)
            return set(out[i] for i in range(min(n, 4096)))
        return self._features_py()

    def _features_py(self):
        s, r = self.read()
        feat = set()
        for v in s:
            feat.add(((0xcbf29ce484222325 ^ v) * 0x100000001b3) & 0xFFFFFFFF)
        for pc, v in r:
            h = ((0xcbf29ce484222325 ^ pc) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
            feat.add(((h ^ v) * 0x100000001b3) & 0xFFFFFFFF)
        return feat

    def read(self):
        scalars, returns = [], []
        n = min(int(self.buf[0]), BUF_WORDS - 1)
        pos = 1
        while pos + 3 <= 1 + n:
            header, pc = self.buf[pos], self.buf[pos + 1]
            rtype = (header >> 28) & 0xF
            nfields = (header >> 24) & 0xF or 1
            rlen = 3 + nfields
            if pos + rlen > 1 + n: break
            if 0xffffffff80000000 <= pc <= 0xffffffffffffff00:
                if rtype == 0xF: returns.append((pc, self.buf[pos + 3]))
                elif rtype == 0xE:
                    for i in range(min(nfields, 4)):
                        v = self.buf[pos + 3 + i]
                        if v < 0x100000000: scalars.append(int(v))
            pos += rlen
        return scalars, returns

    def count_success_returns(self):
        """Count functions that returned 0 (success = bypassed validation, deeper path).
        Returns (success_count, total_returns, new_error_codes)."""
        n = min(int(self.buf[0]), BUF_WORDS - 1)
        pos = 1
        success = 0
        total = 0
        errors = set()
        while pos + 3 <= 1 + n:
            header, pc = self.buf[pos], self.buf[pos + 1]
            rtype = (header >> 28) & 0xF
            nfields = (header >> 24) & 0xF or 1
            rlen = 3 + nfields
            if pos + rlen > 1 + n: break
            if 0xffffffff80000000 <= pc <= 0xffffffffffffff00 and rtype == 0xF:
                ret_val = self.buf[pos + 3]
                total += 1
                if ret_val == 0:
                    success += 1
                elif ret_val < 0x1000:  # small positive/negative = error code
                    errors.add(int(ret_val))
                elif ret_val > 0xFFFFFFFFFFFFFF00:  # negative errno (two's complement)
                    errors.add(int(ret_val) - 0x10000000000000000)
            pos += rlen
        return success, total, errors

# ─── C Extension ──────────────────────────────────────────────────────────────

_harness = None
def _load_harness():
    global _harness
    if _harness is None:
        so = SCRIPT_DIR / 'sniper' / 'harness.so'
        if so.exists():
            _harness = ctypes.CDLL(str(so))
            _harness.harness_pwrite.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_int]
            _harness.harness_truncate.argtypes = [ctypes.c_long]
            _harness.harness_xattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            _harness.harness_fallocate.argtypes = [ctypes.c_long, ctypes.c_long]
    return _harness

def do_write(fp, off, data):
    h = _load_harness()
    if h: h.harness_pwrite(off, data, len(data))
    else:
        fd = os.open(fp, os.O_WRONLY|os.O_CREAT, 0o666); os.lseek(fd, off, 0); os.write(fd, data); os.close(fd)

def do_truncate(fp, sz):
    h = _load_harness()
    if h: h.harness_truncate(sz & 0x7FFFFFFF)
    else:
        try: os.truncate(fp, sz & 0x7FFFFFFF)
        except OSError: pass

def do_xattr(fp, name, val):
    h = _load_harness()
    if h: h.harness_xattr(name.encode(), val, len(val))
    else:
        try: os.setxattr(fp, name, val)
        except OSError: pass

def do_lock(fp):
    import fcntl
    try:
        fd = os.open(fp, os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
    except OSError: pass

def do_read(fp, off, size):
    try:
        fd = os.open(fp, os.O_RDONLY); os.lseek(fd, off, 0); os.read(fd, size); os.close(fd)
    except OSError: pass

def do_rename(fp, worker_id):
    dst = f'{MOUNT}/fuzz_rename_{worker_id}'
    try: os.rename(fp, dst); os.rename(dst, fp)
    except OSError: pass

def do_unlink_create(fp):
    """unlink + recreate (exercises FILE_DISPOSITION + CREATE)."""
    try: os.unlink(fp); Path(fp).write_bytes(b'x')
    except OSError: pass

def do_symlink(fp, worker_id):
    link = f'{MOUNT}/fuzz_link_{worker_id}'
    try: os.unlink(link)
    except OSError: pass
    try: os.symlink(fp, link)
    except OSError: pass

def do_readdir():
    try: os.listdir(MOUNT)
    except OSError: pass

def do_copy_range(fp, worker_id):
    dst = f'{MOUNT}/fuzz_dst_{worker_id}'
    try:
        sfd = os.open(fp, os.O_RDONLY)
        dfd = os.open(dst, os.O_WRONLY|os.O_CREAT, 0o666)
        os.copy_file_range(sfd, dfd, 4096)
        os.close(sfd); os.close(dfd)
    except (OSError, AttributeError): pass

# ─── VFS Operations Strategy Map ──────────────────────────────────────────────

VFS_OPS: dict[str, Callable] = {
    'write': do_write,
    'truncate': do_truncate,
    'xattr': do_xattr,
    'lock': do_lock,
    'read': do_read,
    'rename': do_rename,
    'unlink': do_unlink_create,
    'symlink': do_symlink,
    'readdir': do_readdir,
    'copy_range': do_copy_range,
}

# ─── Raw PDU helpers ──────────────────────────────────────────────────────────

def _smb2_hdr(cmd, mid, tid=0, sid=0):
    h = bytearray(64)
    h[0:4] = b'\xfeSMB'
    struct.pack_into('<H', h, 4, 64)
    struct.pack_into('<H', h, 6, 1)
    struct.pack_into('<H', h, 12, cmd)
    struct.pack_into('<H', h, 14, 1)
    struct.pack_into('<Q', h, 24, mid)
    struct.pack_into('<I', h, 36, tid)
    struct.pack_into('<Q', h, 40, sid)
    return bytes(h)

def _raw_send(sock, pdu):
    try:
        sock.sendall(struct.pack('>I', len(pdu)) + pdu)
        sock.settimeout(2)
        hdr = b''
        while len(hdr) < 4:
            c = sock.recv(4 - len(hdr))
            if not c: return None
            hdr += c
        rlen = struct.unpack('>I', hdr)[0]
        if rlen > 1048576: return b'ERR'
        resp = b''
        while len(resp) < rlen:
            c = sock.recv(min(rlen - len(resp), 65536))
            if not c: break
            resp += c
        return resp
    except (socket.timeout, ConnectionError, BrokenPipeError, OSError):
        return None

# ─── Worker Cycle ─────────────────────────────────────────────────────────────

@dataclass
class FuzzWorker:
    """Single fuzzing worker cycle.
    
    Encapsulates worker state and delegates to phase implementations.
    Use: result = FuzzWorker.execute(worker_id, vpool, corpus, features)
    """
    worker_id: int
    vpool: list
    seed_corpus: list
    seed_features: list

    @staticmethod
    def execute(args: tuple) -> tuple:
        """Entry point for multiprocessing.Pool.map — wraps with error handling."""
        try:
            return _run_one_cycle_impl(args)
        except Exception:
            import traceback
            traceback.print_exc()
            return (0, 0, 0, 0, [], [], [])


def run_one_cycle(args):
    """Single worker cycle (backward-compatible entry point)."""
    return FuzzWorker.execute(args)

def _remount_cifs():
    """Remount CIFS share after ksmbd crash/recovery."""
    return _service.restart_and_remount()


def _run_one_cycle_impl(args):
    """Single worker cycle. args = (worker_id, shared_value_pool_proxy, seed_corpus, seed_features)"""
    worker_id, vpool_proxy, seed_corpus, seed_features = args
    fpath = f'{MOUNT}/fuzz_{worker_id}'
    try:
        Path(fpath).write_bytes(b'x')
    except OSError:
        # CIFS mount dead — try to recover
        try:
            _remount_cifs()
            Path(fpath).write_bytes(b'x')
        except:
            return (0, 0, 0, 0, [], [], [])  # skip this cycle
    df = DfRemote()
    h = _load_harness()
    if h: h.harness_open(fpath.encode())

    # Phase 0: calibration
    noisy_pcs = set()
    ret_sets = []
    for _ in range(3):
        df.enable(); do_write(fpath, 0, b'STABLE'); df.disable()
        _, rets = df.read()
        ret_sets.append(set((pc, v) for pc, v in rets))
    if ret_sets:
        stable = ret_sets[0] & ret_sets[1] & ret_sets[2]
        noisy_pcs = {pc for pc, v in ((ret_sets[0]|ret_sets[1]|ret_sets[2]) - stable)}

    # Seed from persistent corpus + shared pool
    all_features = set(seed_features)
    corpus = [(off, data, rank) for off, data, rank in seed_corpus]
    value_pool = list(vpool_proxy) if vpool_proxy else [0, 64, 4096, 0x1000, 0xFFFF]

    # Phase 1: discovery (5000 iters)
    new_values = []
    for _ in range(5000):
        if corpus and random.random() < 0.7:
            c = random.choices(corpus, weights=[r for _, _, r in corpus])[0]
            offset = c[0] ^ (1 << random.randint(0, 20))
            data = bytearray(c[1])
            if data: data[random.randint(0, len(data)-1)] ^= random.randint(1, 255)
            data = bytes(data)
        else:
            offset = random.choice(value_pool) if value_pool else random.randint(0, 0xFFFF)
            data = os.urandom(random.choice([1, 64, 4096, 4095, 8192]))

        df.enable()
        op = random.choice(['write','write','truncate','xattr','lock',
                           'read','rename','unlink','symlink','readdir','copy_range'])
        if op == 'write': do_write(fpath, offset & 0xFFFFFF, data)
        elif op == 'truncate': do_truncate(fpath, offset)
        elif op == 'xattr': do_xattr(fpath, f'user.f{random.randint(0,99)}', data[:256])
        elif op == 'lock': do_lock(fpath)
        elif op == 'read': do_read(fpath, offset & 0xFFFFFF, len(data))
        elif op == 'rename': do_rename(fpath, worker_id)
        elif op == 'unlink': do_unlink_create(fpath)
        elif op == 'symlink': do_symlink(fpath, worker_id)
        elif op == 'readdir': do_readdir()
        elif op == 'copy_range': do_copy_range(fpath, worker_id)
        else: do_lock(fpath)
        df.disable()

        features = df.features_fast()
        # Return-value-aware: count how many functions returned 0 (success = deeper path)
        success_cnt, total_ret, err_codes = df.count_success_returns()
        # Also collect raw scalars for value_pool
        scalars, _ = df.read()
        for v in scalars:
            if 0 < v < 0x100000000:
                new_values.append(v)

        # Sharp: anomaly detection (ret=0 for arg > 2× prev max)
        try:
            # sharp merged below
            entries = [(pc, val) for pc, val in zip(scalars[::2], scalars[1::2]) if pc > 0xffffffff80000000]
            returns = [(pc, val) for pc, val in zip(scalars[::2], scalars[1::2]) if val == 0]
            check_anomaly(entries, returns)
        except: pass

        new = features - all_features
        if new:
            all_features.update(new)
            # Rank: new features + bonus for success returns (bypassed validation)
            rank = len(new) + (success_cnt * 2)
            corpus.append((offset, data, rank))
            # Sharp: record sequence that reached new coverage
            try:
                # sharp merged below
                record_operation([(op, offset)], list(features)[:20])
            except: pass

    # Feed new values back to shared pool
    corpus.sort(key=lambda x: x[2], reverse=True)
    corpus.sort(key=lambda x: x[2], reverse=True)
    corpus = corpus[:512]

    # Phase 2: adaptive sniper (boundaries from transitions)
    boundaries = [0, 1, 0xFF, 0x1000, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]
    # Add adaptive boundaries from value_pool
    for v in value_pool[:20]:
        if 0 < v < 0x1000000:
            boundaries.extend([v-1, v, v+1])
    boundaries = list(set(boundaries))

    transitions = 0
    total = 0
    transition_values = []  # track which values caused transitions

    for idx in range(min(len(corpus), 50)):
        base_off, base_data, _ = corpus[idx]
        df.enable(); do_write(fpath, base_off & 0xFFFFFF, base_data); df.disable()
        _, base_rets = df.read()
        base_sig = {(pc, v) for pc, v in base_rets}

        for bval in boundaries[:25]:
            df.enable(); do_write(fpath, bval & 0xFFFFFF, base_data); df.disable()
            _, new_rets = df.read()
            new_sig = {(pc, v) for pc, v in new_rets}
            total += 1
            diff = {(pc, v) for pc, v in new_sig.symmetric_difference(base_sig) if pc not in noisy_pcs}
            if diff:
                transitions += 1
                transition_values.append(bval)

        # Race
        import threading
        t1 = threading.Thread(target=do_write, args=(fpath, base_off & 0xFFFFFF, os.urandom(4096)))
        t2 = threading.Thread(target=do_truncate, args=(fpath, base_off & 0xFFFF))
        df.enable(); t1.start(); t2.start(); t1.join(); t2.join(); df.disable()
        total += 1

    # Phase 3: raw PDU — dynamic mutations from value_pool + coverage-guided
    raw_transitions = 0
    try:
        from smbprotocol.connection import Connection, Dialects
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
        from smbprotocol.open import Open, CreateDisposition, ShareAccess, CreateOptions
        import uuid

        conn = Connection(uuid.uuid4(), "127.0.0.1", 445)
        conn.connect(dialect=Dialects.SMB_3_1_1)
        sess = Session(conn, "fuzz", "fuzz", require_encryption=True)
        sess.connect()
        tree = TreeConnect(sess, "\\\\127.0.0.1\\share")
        tree.connect()
        f = Open(tree, f"fuzz_raw_{worker_id}")
        f.create(0, 0x12019F, 0x80,
                 ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                 CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
        file_id = f.file_id
        sid, tid = sess.session_id, tree.tree_connect_id
        mid = conn.sequence_window['low'] + 100
        sock = conn.transport._sock
        conn.transport._sock = None
        conn.transport.connected = False

        # Coverage-guided: track hits per PDU type, send more of winners
        pdu_hits = {'ioctl': 0, 'querydir': 0, 'lock': 0, 'read': 0, 'write': 0, 'close': 0}

        def raw_pdu(cmd, body, ptype='ioctl'):
            nonlocal mid, raw_transitions
            hdr = _smb2_hdr(cmd, mid, tid, sid); mid += 1
            df.enable(); _raw_send(sock, hdr + body); df.disable()
            if df.features_fast():
                raw_transitions += 1
                pdu_hits[ptype] += 1

        # Pick values from pool for dynamic mutations
        pool_vals = list(value_pool[-200:]) if value_pool else [0, 0xFFFF, 0x7FFFFFFF]
        tv = transition_values if transition_values else [0, 0x1000, 0xFFFFFFFF]

        # Dynamic IOCTL mutations
        for _ in range(8):
            v1 = random.choice(pool_vals + tv)
            v2 = random.choice(pool_vals + tv)
            ctl = random.choice([0x000980C8, 0x000940CF, 0x001480044, 0x00098344, 0x00140204])
            if ctl in (0x000980C8, 0x000940CF):
                payload = struct.pack('<qq', v1, v2)
            elif ctl == 0x001480044:
                payload = b'\x00'*24 + struct.pack('<II', v1 & 0xFFFFFFFF, 0) + struct.pack('<qqII', v2, v2, v1 & 0xFFFFFFFF, 0)
            else:
                payload = os.urandom(min(abs(v1 & 0xFF) + 16, 128))
            body = struct.pack('<HHI', 57, 0, ctl) + file_id
            body += struct.pack('<IIIIIII', 120, len(payload), 0, 0, 0, 4096, 1) + struct.pack('<I', 0) + payload
            raw_pdu(0x000B, body, 'ioctl')

        # Dynamic QUERY_DIR
        for _ in range(6):
            cls = random.choice([0, 1, 2, 3, 12, 37, 38, 60, 99, 128, 255])
            obl = random.choice(pool_vals + [0, 0xFFFF, 0xFFFFFFFF]) & 0xFFFFFFFF
            pat = random.choice([b'*\x00', b'?\x00', os.urandom(random.randint(2,64)), b'\xff'*32])
            body = struct.pack('<HBBI', 33, cls, random.randint(0,0xFF), 0) + file_id
            body += struct.pack('<HHI', 96, len(pat), obl) + pat
            raw_pdu(0x000E, body, 'querydir')

        # Dynamic LOCK
        for _ in range(4):
            off = random.choice(pool_vals + tv) & 0xFFFFFFFFFFFFFFFF
            length = random.choice(pool_vals + tv) & 0xFFFFFFFFFFFFFFFF
            flags = random.choice([0x01, 0x02, 0x10, 0x20, 0x21, 0xFF])
            body = struct.pack('<HI', 48, 1) + file_id + struct.pack('<qqII', off, length, flags, 0)
            raw_pdu(0x000A, body, 'lock')

        # Dynamic READ
        for _ in range(4):
            roff = random.choice(pool_vals + tv) & 0xFFFFFFFFFFFFFFFF
            rlen = random.choice(pool_vals + [0xFFFFFFFF, 0, 1]) & 0xFFFFFFFF
            body = struct.pack('<HBIQI', 49, 0, rlen, roff, 0) + file_id + struct.pack('<III', 0, 0, 0)
            raw_pdu(0x0008, body, 'read')

        # Dynamic WRITE with extreme values
        for v in tv[:6]:
            body = struct.pack('<HHI', 49, random.choice([0, 64, 113, 0xFFFF]) & 0xFFFF, random.choice(pool_vals) & 0xFFFFFFFF)
            body += struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF) + file_id
            body += struct.pack('<IIHHI', 0, 0, 0, 0, random.randint(0, 0xFFFFFFFF)) + b'\x00' + os.urandom(64)
            raw_pdu(0x0009, body, 'write')

        # CLOSE with stale/garbage FileId
        for _ in range(3):
            body = struct.pack('<HHI', 24, 0, 0) + os.urandom(16)
            raw_pdu(0x0006, body, 'close')

        # Coverage-guided bonus: send 5 more of the most productive PDU type
        best = max(pdu_hits, key=pdu_hits.get) if any(pdu_hits.values()) else 'ioctl'
        for _ in range(5):
            v = random.choice(pool_vals + tv)
            if best == 'ioctl':
                payload = struct.pack('<qq', v, random.choice(pool_vals))
                body = struct.pack('<HHI', 57, 0, 0x000980C8) + file_id
                body += struct.pack('<IIIIIII', 120, len(payload), 0, 0, 0, 4096, 1) + struct.pack('<I', 0) + payload
                raw_pdu(0x000B, body, 'ioctl')
            elif best == 'querydir':
                body = struct.pack('<HBBI', 33, random.randint(0,255), 0, 0) + file_id
                body += struct.pack('<HHI', 96, 2, v & 0xFFFFFFFF) + b'*\x00'
                raw_pdu(0x000E, body, 'querydir')
            elif best == 'lock':
                body = struct.pack('<HI', 48, 1) + file_id + struct.pack('<qqII', v, v, 0x21, 0)
                raw_pdu(0x000A, body, 'lock')
            else:
                body = struct.pack('<HHI', 49, 113, v & 0xFFFFFFFF) + struct.pack('<Q', v) + file_id
                body += struct.pack('<IIHHI', 0, 0, 0, 0, 0) + b'\x00' + os.urandom(64)
                raw_pdu(0x0009, body, 'write')

        sock.close()
    except Exception:
        pass

    # Phase 4: TRUE parallel raw TCP races (no smbprotocol serialization)
    try:
        # smb_proto merged below
        import sys; sys.path.insert(0, str(SCRIPT_DIR))

        df.enable()
        parallel_session_race(n_conns=4, target_file=f'fuzz_race_{worker_id}')
        df.disable()
        feat = df.features_fast()
        new = feat - all_features
        if new:
            all_features.update(new)
            raw_transitions += len(new)
    except Exception:
        # Fallback: use threading with smbprotocol
        try:
            import threading, uuid
            from smbprotocol.connection import Connection, Dialects
            from smbprotocol.session import Session
            from smbprotocol.tree import TreeConnect
            from smbprotocol.open import Open, CreateDisposition, ShareAccess, CreateOptions

            race_file = f"fuzz_race_{worker_id}"
            def make_session():
                c = Connection(uuid.uuid4(), "127.0.0.1", 445)
                c.connect(dialect=Dialects.SMB_3_1_1)
                s = Session(c, "fuzz", "fuzz", require_encryption=True)
                s.connect()
                t = TreeConnect(s, "\\\\127.0.0.1\\share")
                t.connect()
                o = Open(t, race_file)
                o.create(0, 0x12019F, 0x80,
                         ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                         CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
                return c, s, t, o

            c1, s1, t1, o1 = make_session()
            c2, s2, t2, o2 = make_session()
            for burst in range(3):
                df.enable()
                def b1():
                    for _ in range(5):
                        try: o1.write(os.urandom(4096), offset=random.randint(0, 0xFFFF))
                        except: pass
                def b2():
                    for _ in range(5):
                        try: o2.write(os.urandom(4096), offset=random.randint(0, 0xFFFF))
                        except: pass
                ta = threading.Thread(target=b1); tb = threading.Thread(target=b2)
                ta.start(); tb.start(); ta.join(); tb.join()
                df.disable()
                feat = df.features_fast()
                new = feat - all_features
                if new: all_features.update(new); raw_transitions += len(new)
            try: o1.close(); t1.disconnect(); s1.disconnect(); c1.disconnect()
            except: pass
            try: o2.close(); t2.disconnect(); s2.disconnect(); c2.disconnect()
            except: pass
        except: pass

    # Phase 5: CVE-pattern targeted attacks
    try:
        import threading, uuid
        from smbprotocol.connection import Connection, Dialects
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
        from smbprotocol.open import Open, CreateDisposition, ShareAccess, CreateOptions

        def _make_conn():
            c = Connection(uuid.uuid4(), "127.0.0.1", 445)
            c.connect(dialect=Dialects.SMB_3_1_1)
            return c

        # 5a. Session setup/teardown race (CVE-2024-50286 pattern)
        # Rapid concurrent session create + disconnect triggers UAF in sessions_table
        def rapid_session_churn():
            for _ in range(10):
                try:
                    c = _make_conn()
                    s = Session(c, "fuzz", "fuzz", require_encryption=True)
                    s.connect()
                    s.disconnect()
                    c.disconnect()
                except: pass

        df.enable()
        threads = [threading.Thread(target=rapid_session_churn) for _ in range(3)]
        for t in threads: t.start()
        for t in threads: t.join()
        df.disable()
        feat = df.features_fast()
        new = feat - all_features
        if new:
            all_features.update(new)
            raw_transitions += len(new)

        # 5b. Malformed SecurityDescriptor / ACL (CVE-2025-22039 pattern)
        # SET_INFO with InfoType=3 (SECURITY) + crafted DACL with overflow offsets
        conn = _make_conn()
        sess = Session(conn, "fuzz", "fuzz", require_encryption=True)
        sess.connect()
        tree = TreeConnect(sess, "\\\\127.0.0.1\\share")
        tree.connect()
        f = Open(tree, f"fuzz_acl_{worker_id}")
        f.create(0, 0x12019F, 0x80,
                 ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                 CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
        file_id = f.file_id
        sid, tid = sess.session_id, tree.tree_connect_id
        mid = conn.sequence_window['low'] + 200
        sock = conn.transport._sock
        conn.transport._sock = None
        conn.transport.connected = False

        # SET_INFO InfoType=3 (SECURITY), with malformed SD
        malformed_sds = [
            # dacloffset=0xFFFFFFFF (CVE-2025-22039 overflow)
            struct.pack('<BBHI', 0, 0, 0x0001, 0x78) + struct.pack('<I', 0) +
            struct.pack('<I', 0x10000) + struct.pack('<I', 0xFFFFFFFF) +
            b'\x00' * 100 + b'\x01\x01\x00\x00\x00\x00\x00\x00' + b'\xCC' * 64,
            # dacloffset past buffer end
            struct.pack('<BBHI', 0, 0, 0x0004, 0) + struct.pack('<III', 0, 0, 200) + b'\x00' * 32,
            # num_subauth=0 (CVE-2025-22038: sub_auth[-1])
            struct.pack('<BBHI', 1, 0, 0x0004, 0x14) + struct.pack('<III', 0, 0x14, 0) +
            b'\x01' + b'\x00' + b'\x00' * 6 + b'\x00' * 60,  # SID with num_subauth=0
            # Huge AclSize in DACL header
            struct.pack('<BBHI', 0, 0, 0x0004, 0x14) + struct.pack('<III', 0, 0x14, 0) +
            struct.pack('<BBHI', 2, 0, 0xFFFF, 1) + b'\x00' * 100,
        ]
        for sd in malformed_sds:
            # SET_INFO: InfoType=3(security), FileInfoClass=0, AdditionalInfo=7(DACL|OWNER|GROUP)
            hdr = _smb2_hdr(0x0011, mid, tid, sid); mid += 1
            body = struct.pack('<H', 33)
            body += struct.pack('<BB', 3, 0)  # InfoType=SECURITY, FileInfoClass=0
            body += struct.pack('<I', len(sd))
            body += struct.pack('<H', 96)
            body += struct.pack('<H', 0)
            body += struct.pack('<I', 7)  # AdditionalInfo = DACL|OWNER|GROUP
            body += file_id
            body += sd
            df.enable(); _raw_send(sock, hdr + body); df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)

        # 5c. Stream write with extreme pos (CVE-2025-37947 pattern)
        # Write to stream with pos >= XATTR_SIZE_MAX (0x10000)
        stream_name = f"fuzz_stream_{worker_id}:stream1"
        for stream_pos in [0x10000, 0x10008, 0x10010, 0x10100, 0xFFFF]:
            hdr = _smb2_hdr(0x0009, mid, tid, sid); mid += 1  # WRITE
            body = struct.pack('<HHI', 49, 113, 64)  # StructSize, DataOffset, Length=64
            body += struct.pack('<Q', stream_pos)  # Offset = extreme pos
            body += file_id
            body += struct.pack('<IIHHI', 0, 0, 0, 0, 0)
            body += b'\x00' + b'\xAA' * 64
            df.enable(); _raw_send(sock, hdr + body); df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)

        # 5d. CREATE with malformed contexts (CVE-2025-22042/22043 pattern)
        # DH2Q context with truncated buffer / Lease context with bad LeaseState
        for ctx_data in [
            # Malformed DH2Q (durable handle v2) — truncated
            b'\x00' * 4 + struct.pack('<I', 32) + b'DH2Q' + b'\x00' * 4 + b'\xFF' * 8,
            # Malformed lease context — huge LeaseState
            b'\x00' * 4 + struct.pack('<I', 52) + b'RqLs' + b'\x00' * 4 +
            os.urandom(16) + struct.pack('<III', 0xFFFFFFFF, 0xFFFFFFFF, 0) + b'\x00' * 16,
            # MxAc context (max access) with garbage
            b'\x00' * 4 + struct.pack('<I', 4) + b'MxAc' + b'\x00' * 4 + b'\xFF' * 100,
        ]:
            hdr = _smb2_hdr(0x0005, mid, tid, sid); mid += 1  # CREATE
            fname = f"fuzz_ctx_{worker_id}".encode('utf-16-le')
            creat_body = struct.pack('<H', 57)
            creat_body += struct.pack('<BB', 0, 0)
            creat_body += struct.pack('<I', 0)
            creat_body += struct.pack('<QQ', 0, 0)
            creat_body += struct.pack('<I', 0x12019F)
            creat_body += struct.pack('<I', 0x80)
            creat_body += struct.pack('<I', 0x07)
            creat_body += struct.pack('<I', 0x05)
            creat_body += struct.pack('<I', 0x40)
            name_offset = 120
            ctx_offset = name_offset + len(fname)
            # Align to 8
            ctx_offset = (ctx_offset + 7) & ~7
            creat_body += struct.pack('<HH', name_offset, len(fname))
            creat_body += struct.pack('<II', ctx_offset, len(ctx_data))
            creat_body += fname
            # Pad to ctx_offset
            pad = ctx_offset - name_offset - len(fname)
            if pad > 0: creat_body += b'\x00' * pad
            creat_body += ctx_data
            df.enable(); _raw_send(sock, hdr + creat_body); df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)

        # 5e. Oplock break race (CVE-2025-37776 pattern)
        # Open file with oplock on one session, disconnect during break
        try:
            c3 = _make_conn()
            s3 = Session(c3, "fuzz", "fuzz", require_encryption=True)
            s3.connect()
            t3 = TreeConnect(s3, "\\\\127.0.0.1\\share")
            t3.connect()
            o3 = Open(t3, f"fuzz_oplock_{worker_id}")
            # Request exclusive oplock
            o3.create(0, 0x12019F, 0x80,
                     ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                     CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE,
                     oplock_level=0x08)  # SMB2_OPLOCK_LEVEL_BATCH
            # Open same file from another session to trigger oplock break
            c4 = _make_conn()
            s4 = Session(c4, "fuzz", "fuzz", require_encryption=True)
            s4.connect()
            t4 = TreeConnect(s4, "\\\\127.0.0.1\\share")
            t4.connect()
            # Disconnect first session while oplock break is in flight
            def open_and_disconnect():
                try:
                    o4 = Open(t4, f"fuzz_oplock_{worker_id}")
                    o4.create(0, 0x12019F, 0x80,
                             ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                             CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
                except: pass
            def disconnect_first():
                import time; time.sleep(0.001)
                try: c3.disconnect()
                except: pass

            df.enable()
            ta = threading.Thread(target=open_and_disconnect)
            tb = threading.Thread(target=disconnect_first)
            ta.start(); tb.start(); ta.join(); tb.join()
            df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)
            try: c4.disconnect()
            except: pass
        except: pass

        # 5f. LOCK→CLOSE→CANCEL race (deferred lock UAF pattern)
        # Triggers stale cancel_fn on async_requests after lock freed
        try:
            c5 = _make_conn()
            s5 = Session(c5, "fuzz", "fuzz", require_encryption=True)
            s5.connect()
            t5 = TreeConnect(s5, "\\\\127.0.0.1\\share")
            t5.connect()
            o5 = Open(t5, f"fuzz_lockcancel_{worker_id}")
            o5.create(0, 0x12019F, 0x80,
                     ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                     CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
            fid5 = o5.file_id
            sid5, tid5 = s5.session_id, t5.tree_connect_id
            mid5 = c5.sequence_window['low'] + 300
            sock5 = c5.transport._sock
            c5.transport._sock = None
            c5.transport.connected = False

            # Send LOCK request (will be deferred if range conflicts)
            lock_body = struct.pack('<HI', 48, 1) + fid5
            lock_body += struct.pack('<qqII', 0, 0x7FFFFFFF, 0x01, 0)  # exclusive
            hdr = _smb2_hdr(0x000A, mid5, tid5, sid5); mid5 += 1
            df.enable(); _raw_send(sock5, hdr + lock_body); df.disable()

            # Send CLOSE immediately (frees the file_lock)
            close_body = struct.pack('<HHI', 24, 0, 0) + fid5
            hdr = _smb2_hdr(0x0006, mid5, tid5, sid5); mid5 += 1
            df.enable(); _raw_send(sock5, hdr + close_body); df.disable()

            # Send CANCEL (fires cancel_fn on potentially freed lock)
            # CANCEL uses the MessageId of the LOCK request
            cancel_hdr = _smb2_hdr(0x000C, mid5 - 2, tid5, sid5)
            df.enable(); _raw_send(sock5, cancel_hdr); df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)
            sock5.close()
        except: pass

        # 5g. Concurrent overlapping LOCK race (list_del corruption pattern)
        try:
            c6 = _make_conn()
            s6 = Session(c6, "fuzz", "fuzz", require_encryption=True)
            s6.connect()
            t6 = TreeConnect(s6, "\\\\127.0.0.1\\share")
            t6.connect()
            o6 = Open(t6, f"fuzz_lockrace_{worker_id}")
            o6.create(0, 0x12019F, 0x80,
                     ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                     CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
            fid6 = o6.file_id
            sid6, tid6 = s6.session_id, t6.tree_connect_id
            mid6 = c6.sequence_window['low'] + 400
            sock6 = c6.transport._sock
            c6.transport._sock = None
            c6.transport.connected = False

            # Rapidly lock + unlock overlapping ranges
            df.enable()
            for _ in range(10):
                off = random.randint(0, 0xFFFF)
                length = random.randint(1, 0xFFFF)
                # LOCK exclusive
                body = struct.pack('<HI', 48, 1) + fid6 + struct.pack('<qqII', off, length, 0x01, 0)
                hdr = _smb2_hdr(0x000A, mid6, tid6, sid6); mid6 += 1
                _raw_send(sock6, hdr + body)
                # UNLOCK same range
                body = struct.pack('<HI', 48, 1) + fid6 + struct.pack('<qqII', off, length, 0x20, 0)
                hdr = _smb2_hdr(0x000A, mid6, tid6, sid6); mid6 += 1
                _raw_send(sock6, hdr + body)
            df.disable()
            feat = df.features_fast()
            new = feat - all_features
            if new:
                all_features.update(new)
                raw_transitions += len(new)
            sock6.close()
        except: pass

        # 5h. WRITE with RDMA ChannelInfoLength mismatch (OOB read pattern)
        # Send WRITE with Channel=RDMA but ChannelInfoLength > actual data
        try:
            for ch_len in [0x100, 0x1000, 0xFFFF]:
                hdr = _smb2_hdr(0x0009, mid, tid, sid); mid += 1
                body = struct.pack('<HHI', 49, 113, 64)  # StructSize, DataOffset, Length
                body += struct.pack('<Q', 0) + file_id   # Offset + FileId
                body += struct.pack('<I', 1)             # Channel = RDMA_V1
                body += struct.pack('<I', 0)             # RemainingBytes
                body += struct.pack('<HH', 120, ch_len)  # WriteChannelInfoOffset, ChannelInfoLength
                body += struct.pack('<I', 0)             # Flags
                body += b'\x00' + b'\xBB' * 64           # Minimal data (shorter than ChannelInfoLength)
                df.enable(); _raw_send(sock, hdr + body); df.disable()
                feat = df.features_fast()
                new = feat - all_features
                if new:
                    all_features.update(new)
                    raw_transitions += len(new)
        except: pass

        sock.close()
    except Exception:
        pass

    # Phase 5b: NDR/DCE-RPC fuzzing over IPC$ pipe (exercises ndr.c parsing)
    try:
        # smb_proto merged below
        ndr_conn = RawSmb2()
        ndr_conn.connect()
        ndr_conn.negotiate()
        ndr_conn.session_setup_ntlmssp()
        # Tree connect to IPC$
        path = '\\\\127.0.0.1\\IPC$'.encode('utf-16-le')
        hdr = smb2_hdr(0x0003, ndr_conn.mid, sid=ndr_conn.sid); ndr_conn.mid += 1
        body = struct.pack('<HHHH', 9, 0, 72, len(path)) + path
        resp = ndr_conn._xact(hdr + body)
        if resp and len(resp) >= 40:
            ndr_conn.tid = struct.unpack_from('<I', resp, 36)[0]
            # Create pipe: \srvsvc
            pipe_name = '\\srvsvc'.encode('utf-16-le')
            hdr = smb2_hdr(0x0005, ndr_conn.mid, ndr_conn.tid, ndr_conn.sid); ndr_conn.mid += 1
            body = struct.pack('<HBB', 57, 0, 0) + struct.pack('<I', 0) + struct.pack('<QQ', 0, 0)
            body += struct.pack('<IIII', 0x12019F, 0, 0x07, 0x01)
            body += struct.pack('<I', 0x00200000)
            body += struct.pack('<HH', 120, len(pipe_name))
            body += struct.pack('<II', 0, 0)
            body += pipe_name
            resp = ndr_conn._xact(hdr + body)
            if resp and len(resp) >= 144:
                pipe_fid = resp[128:144]
                # Send mutated DCE/RPC bind + request over the pipe via IOCTL/FSCTL_PIPE_TRANSCEIVE
                df.enable()
                for _ in range(20):
                    # DCE/RPC header: version(1)=5, minor(1)=0, type(1)=0(request), flags(1)
                    rpc = bytearray(24)
                    rpc[0] = 5; rpc[1] = 0
                    rpc[2] = random.choice([0, 11, 12, 14])  # request/bind/alter_ctx/orphaned
                    rpc[3] = random.randint(0, 0xFF)
                    rpc[4:8] = b'\x10\x00\x00\x00'  # data representation
                    # Frag length (mutated)
                    frag_len = random.randint(24, 256)
                    struct.pack_into('<H', rpc, 8, frag_len)
                    # Call ID
                    struct.pack_into('<I', rpc, 12, random.randint(0, 0xFFFF))
                    # Mutated payload
                    rpc += os.urandom(random.randint(8, 200))

                    # IOCTL(FSCTL_PIPE_TRANSCEIVE=0x0011C017) with pipe_fid
                    hdr = smb2_hdr(CMD_IOCTL, ndr_conn.mid, ndr_conn.tid, ndr_conn.sid)
                    ndr_conn.mid += 1
                    ioctl_body = struct.pack('<HH', 57, 0)
                    ioctl_body += struct.pack('<I', 0x0011C017)  # FSCTL_PIPE_TRANSCEIVE
                    ioctl_body += pipe_fid
                    ioctl_body += struct.pack('<II', 120, len(rpc))  # input offset, count
                    ioctl_body += struct.pack('<I', 4096)  # max input
                    ioctl_body += struct.pack('<II', 0, 0)  # output offset/count
                    ioctl_body += struct.pack('<I', 4096)  # max output
                    ioctl_body += struct.pack('<I', 1)  # flags = SMB2_0_IOCTL_IS_FSCTL
                    ioctl_body += struct.pack('<I', 0)  # reserved
                    ioctl_body += bytes(rpc)
                    ndr_conn._send(hdr + ioctl_body)
                df.disable()
                feat = df.features_fast()
                new = feat - all_features
                if new:
                    all_features.update(new)
                    raw_transitions += len(new)
        ndr_conn.disconnect()
    except Exception:
        pass

    # Check bugs (only after KSMBD starts — filter boot-time warnings)
    bugs = os.popen("dmesg | tail -200 | grep -cE 'BUG:.*ksmbd|BUG:.*smb|UBSAN:.*smb|UBSAN:.*ksmbd|possible circular.*ksmbd|sleeping.*atomic.*ksmbd' 2>/dev/null").read().strip()
    # Also check generic KASAN (any slab-out-of-bounds after init)
    kasan = os.popen("dmesg | tail -200 | grep -c 'BUG: KASAN' 2>/dev/null").read().strip()
    bug_count = (int(bugs) if bugs.isdigit() else 0) + (int(kasan) if kasan.isdigit() else 0)

    return (len(all_features), transitions, raw_transitions, bug_count,
            [(off, data.hex(), rank) for off, data, rank in corpus[:256]],
            list(all_features)[:10000], new_values[:500])

# ─── Fuzz Command ─────────────────────────────────────────────────────────────

def _seed_audit_corpus():
    """Seed sniper persistent corpus with exact audit boundary values."""
    corpus_dir = Path('/tmp/ksmbdzzer_corpus_persistent')
    corpus_dir.mkdir(exist_ok=True)
    seeds = {
        'sniper_raw_write': [
            # #3: loff_t overflow offsets
            struct.pack('<QI', 0x7FFFFFFFFFFFFFF0, 32),
            struct.pack('<QI', 0x7FFFFFFFFFFFFFFE, 16),
            struct.pack('<QI', 0x7FFFFFFFFFFFF000, 4096),
        ],
        'sniper_compound': [
            # #1: DataOffset OOB (bit 0x20 set + large offset byte)
            b'\x20\xff' + struct.pack('<I', 0x1000) + b'A' * 64,
            # #2: AllocationSize overflow (bit 0x40 set + index)
            b'\x40\x00' + struct.pack('<I', 0) + b'B' * 64,
            b'\x40\x01' + struct.pack('<I', 0) + b'C' * 64,
        ],
        'sniper_dacl_setinfo': [
            # #4: BufferOffset OOB (bit 0x10 set + large offset)
            b'\x10\x3f' + b'\x00' * 18 + b'\x02\x00\x01\x00' + b'D' * 200,
            # #5: DENY ACE with MAXIMAL_ACCESS
            b'\x00\x00' + b'\x00' * 2 + b'\x01\x00' + b'\x01\x05' + struct.pack('<I', 0x02000000) + b'E' * 100,
        ],
    }
    for sniper_name, seed_list in seeds.items():
        d = corpus_dir / sniper_name
        d.mkdir(exist_ok=True)
        for i, data in enumerate(seed_list):
            f = d / f'audit_seed_{i:02d}'
            if not f.exists():
                f.write_bytes(data)


@dataclass
class FuzzCampaign:
    """Orchestrates multi-round fuzzing campaigns.
    
    Encapsulates state that persists across rounds:
    corpus, features, value pool, peak metrics, history.
    """
    cfg: Config = field(default_factory=lambda: CFG)
    service: KsmbdService = field(default_factory=KsmbdService)
    seed_corpus: list = field(default_factory=list)
    global_features: set = field(default_factory=set)
    value_pool: list = field(default_factory=list)
    history: list = field(default_factory=list)
    peak_feat: int = 0

    def load_corpus(self) -> None:
        self.seed_corpus, self.global_features, self.value_pool = corpus_load()
        if self.seed_corpus:
            print(f"  Loaded corpus: {len(self.seed_corpus)} entries, "
                  f"{len(self.global_features)} features, {len(self.value_pool)} pool values")

    def save_corpus(self) -> None:
        corpus_save(self.seed_corpus, self.global_features, self.value_pool)

    def check_recovery(self, round_feat: int) -> None:
        """Restart ksmbd if features dropped >50% from peak."""
        self.peak_feat = max(self.peak_feat, round_feat)
        if round_feat < self.peak_feat * 0.5 or round_feat == 0:
            print(f"  [recovery] Features dropped ({round_feat} < {self.peak_feat}×50%), restarting ksmbd...")
            self.service.restart_and_remount()
            time.sleep(2)

    def record_round(self, elapsed: float, cum_features: int, corpus_size: int, rnd: int) -> None:
        self.history.append((elapsed, cum_features, corpus_size, rnd))

    def print_histogram(self) -> None:
        if not self.history: return
        print(f"\n  Coverage & Corpus over Time")
        print(f"  {'─'*56}")
        max_feat = max(h[1] for h in self.history) or 1
        width = 40
        for elapsed_s, cum_feat, corpus_sz, _ in self.history:
            t_min = elapsed_s / 60
            feat_bar = int((cum_feat / max_feat) * width)
            print(f"  {t_min:5.1f}m │{'█' * feat_bar}{'░' * (width - feat_bar)}│ {cum_feat:>7} feat")
            print(f"       │{'▓' * (corpus_sz * width // 600)}{' ' * (width - corpus_sz * width // 600)}│ {corpus_sz:>5} corpus")
        print(f"  {'─'*56}")
        print(f"  █ = cumulative features  ▓ = corpus size")
        report_path = Path('/tmp/ksmbdzzer_report.csv')
        with open(report_path, 'w') as f:
            f.write("elapsed_sec,cumulative_features,corpus_size,round\n")
            for h in self.history:
                f.write(f"{h[0]:.1f},{h[1]},{h[2]},{h[3]}\n")
        print(f"  CSV: {report_path}")


# Global campaign instance (used by cmd_fuzz/cmd_validate)
_campaign = FuzzCampaign()


def cmd_fuzz(args):
    rounds, procs = args.rounds, args.procs

    # Pre-flight: verify CIFS mount is alive, recover if not
    try:
        Path(f'{MOUNT}/fuzz_target').write_bytes(b'x')
    except OSError:
        print("  [recovery] CIFS mount dead at start, recovering...")
        _remount_cifs()

    # Parse timeout (-t 30m, 1h, 90s, etc.)
    deadline = None
    timeout_str = getattr(args, 't', None)
    if timeout_str:
        val = timeout_str.strip()
        if val.endswith('h'): deadline = time.time() + float(val[:-1]) * 3600
        elif val.endswith('m'): deadline = time.time() + float(val[:-1]) * 60
        elif val.endswith('s'): deadline = time.time() + float(val[:-1])
        else: deadline = time.time() + float(val)
        rounds = 99999  # run until timeout

    print(f"=== ksmbdzzer — KSMBD Dataflow-Guided Fuzzer ===")
    print(f"Rounds: {rounds}, Workers: {procs}, Corpus: {CORPUS_DB}")
    if deadline:
        print(f"Timeout: {timeout_str} (deadline in {deadline - time.time():.0f}s)")
    print()

    # Load persistent corpus
    _campaign.load_corpus()
    seed_corpus = _campaign.seed_corpus
    global_features = _campaign.global_features
    global_vpool = _campaign.value_pool

    mgr = None
    shared_vpool = global_vpool[:4096]  # plain list (no Manager — stable for long runs)

    t0 = time.time()
    total_feat = total_trans = total_raw = 0

    for rnd in range(1, rounds + 1):
        print(f"--- Round {rnd}/{rounds} ---")

        # Timeout check: save corpus and exit gracefully
        if deadline and time.time() >= deadline:
            print(f"  [timeout] Reached deadline, saving corpus and exiting...")
            corpus_save(seed_corpus, global_features, list(shared_vpool))
            break

        # Toggle FAILSLAB: even rounds = injection ON (prob=20), odd = OFF
        if rnd % 2 == 0:
            os.system("echo 20 > /sys/kernel/debug/failslab/probability 2>/dev/null")
            os.system("echo 2 > /sys/kernel/debug/failslab/interval 2>/dev/null")
        else:
            os.system("echo 0 > /sys/kernel/debug/failslab/probability 2>/dev/null")

        # Prepare seed for workers
        seed_c = [(off, bytes.fromhex(d), r) for off, d, r in seed_corpus[:256]]
        seed_f = list(global_features)[:20000]

        if procs > 1:
            with multiprocessing.Pool(procs) as pool:
                results = pool.map(run_one_cycle,
                    [(w, shared_vpool, seed_c, seed_f) for w in range(procs)])
        else:
            results = [run_one_cycle((0, shared_vpool, seed_c, seed_f))]

        # Merge results
        round_feat = round_trans = round_raw = 0
        for feat, trans, raw_t, bugs, new_corpus, new_feats, new_vals in results:
            round_feat += feat
            round_trans += trans
            round_raw += raw_t
            global_features.update(new_feats)
            shared_vpool.extend(new_vals[:200])
            if len(shared_vpool) > 4096:
                shared_vpool = shared_vpool[-4096:]
            # Merge corpus
            for off, dhex, rank in new_corpus:
                seed_corpus.append((off, dhex, rank))
            if bugs > 0:
                print(f"  !!! BUG DETECTED !!!")
                os.system("dmesg | tail -100 | grep -B1 -A15 'KASAN\\|ksmbd\\|smb2' | head -40")
                # Export crash reproducer
                from sniper import CRASH_DIR
                import shutil
                CRASH_DIR.mkdir(exist_ok=True)
                crash_dir = CRASH_DIR / f'worker_bug_{int(time.time())}'
                crash_dir.mkdir(exist_ok=True)
                dmesg_out = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5)
                (crash_dir / 'dmesg.txt').write_text(dmesg_out.stdout[-5000:])
                (crash_dir / 'corpus.json').write_text(json.dumps(
                    [{'offset': o, 'data': d, 'rank': r} for o, d, r in seed_corpus[:64]]))
                print(f"  Crash exported → {crash_dir}")
                corpus_save(seed_corpus, global_features, list(shared_vpool))
                print(f"\n=== BUG FOUND in {time.time()-t0:.0f}s ===")
                return

        # Shrink corpus to top 512
        seed_corpus.sort(key=lambda x: x[2], reverse=True)
        seed_corpus = seed_corpus[:512]

        # Recovery: if features dropped >50% from peak or zero, restart ksmbd
        _campaign.check_recovery(round_feat)

        total_feat += round_feat
        total_trans += round_trans
        total_raw += round_raw
        print(f"  features={round_feat} transitions={round_trans} raw_pdu={round_raw} "
              f"corpus={len(seed_corpus)} pool={len(shared_vpool)}")
        _campaign.record_round(time.time() - t0, total_feat, len(seed_corpus), rnd)

        # Phase 6 (per-round): auto-generated sniper harnesses + generic libFuzzer
        try:
            import sys; sys.path.insert(0, str(SCRIPT_DIR))
            from sniper import generate_all_snipers, run_snipers, should_regenerate, generate_discovery_snipers

            # Generate snipers from value_pool (first round only — they persist)
            if rnd == 1:
                vpool_list = list(shared_vpool)
                snipers = generate_all_snipers(vpool_list)
                if snipers:
                    print(f"  [snipers] generated {len(snipers)} targeted harnesses")
                    # Seed persistent corpus with audit boundary values
                    _seed_audit_corpus()
            elif should_regenerate(list(shared_vpool)):
                vpool_list = list(shared_vpool)
                snipers = generate_all_snipers(vpool_list)
                print(f"  [snipers] regenerated ({len(snipers)} harnesses, pool grew >2×)")

            # Write live dictionary (Phase 1-5 values → snipers reload per-run)
            if snipers:
                live_dict = Path('/tmp/ksmbdzzer_live.dict')
                vpool_now = list(shared_vpool)[-200:]
                with open(live_dict, 'w') as df:
                    for v in set(vpool_now):
                        if 0 < v < 0x100000000:
                            df.write(f'"{struct.pack("<I", v & 0xFFFFFFFF).hex()}"\n')

            # Filter snipers by target focus
            target = getattr(args, 'target', 'all')
            sniper_time = getattr(args, 'sniper_time', 3)
            TARGET_MAP = {
                'write': ['raw_write', 'read_after_write', 'dacl_setinfo', 'compound', 'mt_race'],
                'race': ['mt_race', 'write_lock_race', 'compound'],
                'dacl': ['dacl_setinfo', 'ea_alignment', 'create_ctx'],
                'boundary': ['raw_write', 'read_after_write'],
                'all': [],  # empty = no filter
            }
            if target != 'all' and snipers:
                allowed = TARGET_MAP.get(target, [])
                snipers = [(b, d) for b, d in snipers if any(a in b for a in allowed)]

            # Run snipers (focused mutation on write-side patterns)
            if snipers:
                crashes = run_snipers(snipers, time_per=sniper_time)
                if crashes:
                    print(f"  !!! SNIPER CRASH: {crashes[0][0]} !!!")
                    os.system("dmesg | tail -50 | grep -B1 -A10 'KASAN\\|ksmbd\\|UBSAN' | head -30")
                    corpus_save(seed_corpus, global_features, list(shared_vpool))
                    return

            # Auto-generate discovery snipers from new (PC, arg) → ret=0 pairs
            vpool_list = list(shared_vpool)
            discoveries = [(v, v ^ 0x1000, 0) for v in vpool_list[-20:]
                          if v > 0xffffffff80000000]  # kernel PCs only
            if discoveries:
                disc_snipers = generate_discovery_snipers(discoveries[:3], vpool_list)
                if disc_snipers:
                    print(f"  [discovery] +{len(disc_snipers)} auto-generated snipers from trace-args")
                    run_snipers(disc_snipers, time_per=sniper_time)

        except Exception:
            snipers = []

    # Save final corpus (includes libFuzzer discoveries)
    corpus_save(seed_corpus, global_features, list(shared_vpool))

    # Phase 7: Sharp analysis (binary search + race + anomaly report)
    try:
        import sys; sys.path.insert(0, str(SCRIPT_DIR))
        # sharp merged below

        class SimpleDf:
            def __init__(self): self._enabled = False
            def enable(self):
                try:
                    fd = os.open('/sys/kernel/debug/kcov_dataflow', os.O_RDWR)
                    import fcntl
                    fcntl.ioctl(fd, KCOV_DF_INIT, BUF_WORDS)
                    fcntl.ioctl(fd, KCOV_DF_REMOTE_ENABLE, 0)
                    self._fd = fd
                    self._enabled = True
                except: self._enabled = False
            def disable(self):
                if self._enabled:
                    try:
                        import fcntl
                        fcntl.ioctl(self._fd, KCOV_DF_REMOTE_DISABLE, 0)
                    except: pass
            def read_words(self): return []

        df = SimpleDf()
        fpath = f'{MOUNT}/fuzz_target'
        print("  [sharp] Running boundary search + race analysis...")
        run_sharp_analysis(df, fpath, shared_vpool, global_features)
        _anomaly_detector.report()
        _sequence_learner.report()
        # Logic-bug detection: trust boundary violations
        # sharp merged below
        _trust_checker.report()
    except Exception:
        pass

    elapsed = time.time() - t0
    print(f"\n{'='*60}")
    print(f"COMPLETE: {rounds} rounds × {procs} workers + libFuzzer in {elapsed:.0f}s")
    print(f"Total features: {total_feat} | Transitions: {total_trans} | Raw PDU: {total_raw}")
    print(f"Persistent corpus: {len(seed_corpus)} entries saved to {CORPUS_DB}")
    print(f"{'='*60}")

    _campaign.print_histogram()

# ─── Main ─────────────────────────────────────────────────────────────────────

def cmd_validate(args):
    """Run a fast validation campaign checking that known CVE patterns trigger bugs.
    Intended for older kernels (6.6-6.11) where the bugs are unpatched."""
    print("=== ksmbdzzer VALIDATE mode ===")
    print(f"Target: detect known CVE patterns on current kernel")
    print()

    # Init
    cmd_init(install_deps=False)

    # Run snipers only (no full discovery — just check if bugs trigger)
    import sys; sys.path.insert(0, str(SCRIPT_DIR))
    from sniper import generate_all_snipers, run_snipers

    snipers = generate_all_snipers([0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF])
    print(f"[*] Generated {len(snipers)} snipers")

    time_per = args.time if hasattr(args, 'time') and args.time else 10
    print(f"[*] Running each sniper for {time_per}s...")
    crashes = run_snipers(snipers, time_per=time_per)

    # Also check dmesg
    bugs = os.popen("dmesg | grep -cE 'BUG:.*ksmbd|BUG:.*smb|UBSAN:.*smb|BUG: KASAN' 2>/dev/null").read().strip()
    bug_count = int(bugs) if bugs.isdigit() else 0

    print()
    if crashes or bug_count > 0:
        print(f"!!! VALIDATION: {len(crashes)} sniper crashes + {bug_count} kernel bugs detected !!!")
        os.system("dmesg | tail -60 | grep -B1 -A10 'KASAN\\|UBSAN\\|ksmbd' | head -40")
    else:
        print(f"VALIDATION: 0 bugs detected — kernel appears patched against tested patterns")
    print(f"Snipers tested: dacl_setinfo, stream_oob, ea_alignment, lock_race, "
          f"create_ctx, ndr_rpc, compound, spnego_auth")


def cmd_campaign(args):
    """Multi-phase write-side campaign optimized for long runs."""
    hours = args.hours
    procs = min(args.procs, 2)  # max 2 — ksmbd can't handle 4 aggressive workers
    total_sec = hours * 3600
    print(f"=== ksmbdzzer CAMPAIGN — {hours}h write-side LPE hunt ===")
    print(f"  Workers: {procs}, Total budget: {total_sec}s")
    print()

    # Phase A: Discovery (15% of time)
    phase_a_rounds = max(5, int(total_sec * 0.15) // 80)
    print(f"--- Phase A: DISCOVERY ({phase_a_rounds} rounds) ---")
    a_args = argparse.Namespace(rounds=phase_a_rounds, procs=procs, target='all', sniper_time=5)
    cmd_fuzz(a_args)

    # Phase B: Deep snipers on write targets (55% of time)
    sniper_deep_time = max(30, int(total_sec * 0.55) // 24)
    print(f"\n--- Phase B: DEEP WRITE ({sniper_deep_time}s/sniper) ---")
    b_args = argparse.Namespace(rounds=4, procs=procs, target='write', sniper_time=sniper_deep_time)
    cmd_fuzz(b_args)
    print(f"  [race phase]")
    r_args = argparse.Namespace(rounds=4, procs=procs, target='race', sniper_time=sniper_deep_time)
    cmd_fuzz(r_args)

    # Phase C: Sharp hunting (20% of time)
    print(f"\n--- Phase C: SHARP HUNTING ---")
    c_args = argparse.Namespace(rounds=5, procs=procs, target='boundary', sniper_time=60)
    cmd_fuzz(c_args)

    # Phase D: Validate
    print(f"\n--- Phase D: FINAL VALIDATION ---")
    d_args = argparse.Namespace(time=30)
    cmd_validate(d_args)

    print(f"\n{'='*60}")
    print(f"CAMPAIGN COMPLETE: {hours}h write-side LPE hunt finished")
    print(f"Check /tmp/ksmbdzzer_crashes/ for any findings")
    print(f"{'='*60}")

    print(f"\n{'='*60}")
    print(f"CAMPAIGN COMPLETE: {hours}h write-side LPE hunt finished")
    print(f"Check /tmp/ksmbdzzer_crashes/ for any findings")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='ksmbdzzer — KSMBD write-side LPE fuzzer')
    sub = parser.add_subparsers(dest='cmd')

    ip = sub.add_parser('init')
    ip.add_argument('--install-deps', action='store_true')

    fp = sub.add_parser('fuzz', help='Write-side focused fuzzing')
    fp.add_argument('-rounds', type=int, default=1)
    fp.add_argument('-procs', type=int, default=2)
    fp.add_argument('-t', type=str, default=None, help='Timeout: 30m, 1h, 5h, 90s (graceful save+exit)')
    fp.add_argument('-target', choices=['all', 'write', 'race', 'dacl', 'boundary'],
                    default='all', help='Focus area')
    fp.add_argument('-sniper-time', type=int, default=3, help='Seconds per sniper')

    cp = sub.add_parser('campaign', help='Multi-phase campaign (hours)')
    cp.add_argument('-hours', type=int, default=5)
    cp.add_argument('-procs', type=int, default=4)

    vp = sub.add_parser('validate')
    vp.add_argument('-time', type=int, default=10)

    args = parser.parse_args()
    if args.cmd == 'init': cmd_init(install_deps=args.install_deps)
    elif args.cmd == 'fuzz': cmd_fuzz(args)
    elif args.cmd == 'validate': cmd_validate(args)
    elif args.cmd == 'campaign': cmd_campaign(args)
    else: parser.print_help()

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


def smb2_hdr(cmd, mid, tid=0, sid=0):
    h = bytearray(64)
    h[0:4] = b'\xfeSMB'
    struct.pack_into('<H', h, 4, 64)
    struct.pack_into('<H', h, 6, 1)
    struct.pack_into('<H', h, 12, cmd)
    struct.pack_into('<H', h, 14, 31)  # request more credits
    struct.pack_into('<Q', h, 24, mid)
    struct.pack_into('<I', h, 36, tid)
    struct.pack_into('<Q', h, 40, sid)
    return bytes(h)


class RawSmb2:
    """Single raw TCP SMB2 connection — no library, no serialization."""

    def __init__(self, host='127.0.0.1', port=445):
        self.host = host
        self.port = port
        self.sock = None
        self.mid = 0
        self.sid = 0
        self.tid = 0
        self.file_id = None
        self.state = 'DISCONNECTED'

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect((self.host, self.port))
        self.state = 'CONNECTED'

    def _send(self, pdu):
        try:
            self.sock.sendall(struct.pack('>I', len(pdu)) + pdu)
        except: pass

    def _recv(self):
        try:
            self.sock.settimeout(2)
            hdr = b''
            while len(hdr) < 4:
                c = self.sock.recv(4 - len(hdr))
                if not c: return None
                hdr += c
            rlen = struct.unpack('>I', hdr)[0]
            if rlen > 1048576: return None
            data = b''
            while len(data) < rlen:
                c = self.sock.recv(min(rlen - len(data), 65536))
                if not c: break
                data += c
            return data
        except: return None

    def _xact(self, pdu):
        self._send(pdu)
        return self._recv()

    def negotiate(self):
        hdr = smb2_hdr(CMD_NEGOTIATE, self.mid); self.mid += 1
        # StructSize=36, DialectCount=1, SecurityMode=1, Reserved=0
        body = struct.pack('<HHHH', 36, 1, 1, 0)
        body += struct.pack('<I', 0) + b'\x00' * 16  # Capabilities + ClientGuid
        body += struct.pack('<IHH', 0, 0, 0)  # NegCtxOffset/Count/Reserved2
        body += struct.pack('<H', 0x0300)  # Dialect: SMB 3.0
        resp = self._xact(hdr + body)
        if resp and len(resp) >= 64:
            self.state = 'NEGOTIATED'
        return resp

    def session_setup_ntlmssp(self, user='fuzz', password='fuzz'):
        """Minimal NTLMSSP negotiate + authenticate (may fail without proper auth)."""
        # NTLMSSP Negotiate
        ntlm_neg = (b'NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2'
                    + b'\x00' * 16)
        # SPNEGO wrap
        ntlmssp_oid = b'\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
        spnego_oid = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
        mech_types = b'\xa0' + bytes([len(ntlmssp_oid) + 2]) + b'\x30' + bytes([len(ntlmssp_oid)]) + ntlmssp_oid
        mech_token = b'\xa2' + bytes([len(ntlm_neg) + 2]) + b'\x04' + bytes([len(ntlm_neg)]) + ntlm_neg
        neg_init = b'\xa0' + bytes([len(mech_types + mech_token) + 2]) + b'\x30' + bytes([len(mech_types + mech_token)]) + mech_types + mech_token
        gss = b'\x60' + bytes([len(spnego_oid + neg_init)]) + spnego_oid + neg_init

        hdr = smb2_hdr(CMD_SESSION_SETUP, self.mid); self.mid += 1
        body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
        body += struct.pack('<HH', 88, len(gss)) + struct.pack('<Q', 0) + gss
        resp = self._xact(hdr + body)
        if resp and len(resp) >= 48:
            self.sid = struct.unpack_from('<Q', resp, 40)[0]
            self.state = 'SESSION'
        return resp

    def tree_connect(self, share='share'):
        path = f'\\\\127.0.0.1\\{share}'.encode('utf-16-le')
        hdr = smb2_hdr(CMD_TREE_CONNECT, self.mid, sid=self.sid); self.mid += 1
        body = struct.pack('<HHHH', 9, 0, 72, len(path)) + path
        resp = self._xact(hdr + body)
        if resp and len(resp) >= 40:
            self.tid = struct.unpack_from('<I', resp, 36)[0]
            self.state = 'TREE'
        return resp

    def create(self, filename='fuzz', contexts=b''):
        fname = filename.encode('utf-16-le')
        hdr = smb2_hdr(CMD_CREATE, self.mid, self.tid, self.sid); self.mid += 1
        body = struct.pack('<HBB', 57, 0, 0)
        body += struct.pack('<I', 0) + struct.pack('<QQ', 0, 0)
        body += struct.pack('<IIII', 0x12019F, 0x80, 0x07, 0x05)
        body += struct.pack('<I', 0x40)
        ctx_offset = 120 + len(fname)
        ctx_offset = (ctx_offset + 7) & ~7
        body += struct.pack('<HH', 120, len(fname))
        body += struct.pack('<II', ctx_offset if contexts else 0, len(contexts))
        body += fname
        if contexts:
            body += b'\x00' * (ctx_offset - 120 - len(fname))
            body += contexts
        resp = self._xact(hdr + body)
        if resp and len(resp) >= 144:
            self.file_id = resp[128:144]
            self.state = 'FILE_OPEN'
        return resp

    def write(self, data, offset=0):
        if not self.file_id: return None
        hdr = smb2_hdr(CMD_WRITE, self.mid, self.tid, self.sid); self.mid += 1
        body = struct.pack('<HHI', 49, 113, len(data))
        body += struct.pack('<Q', offset) + self.file_id
        body += struct.pack('<IIHHI', 0, 0, 0, 0, 0) + b'\x00' + data
        return self._xact(hdr + body)

    def set_info(self, info_type, info_class, buf, additional_info=0):
        if not self.file_id: return None
        hdr = smb2_hdr(CMD_SET_INFO, self.mid, self.tid, self.sid); self.mid += 1
        body = struct.pack('<HBB', 33, info_type, info_class)
        body += struct.pack('<I', len(buf)) + struct.pack('<HHI', 96, 0, additional_info)
        body += self.file_id + buf
        return self._xact(hdr + body)

    def lock(self, offset=0, length=0xFFFF, flags=0x01):
        if not self.file_id: return None
        hdr = smb2_hdr(CMD_LOCK, self.mid, self.tid, self.sid); self.mid += 1
        body = struct.pack('<HI', 48, 1) + self.file_id
        body += struct.pack('<qqII', offset, length, flags, 0)
        return self._xact(hdr + body)

    def close(self):
        if not self.file_id: return None
        hdr = smb2_hdr(CMD_CLOSE, self.mid, self.tid, self.sid); self.mid += 1
        body = struct.pack('<HHI', 24, 0, 0) + self.file_id
        resp = self._xact(hdr + body)
        self.file_id = None
        self.state = 'TREE'
        return resp

    def send_raw(self, cmd, body):
        """Send arbitrary command body — for fuzzing."""
        hdr = smb2_hdr(cmd, self.mid, self.tid, self.sid); self.mid += 1
        self._send(hdr + body)

    def send_raw_recv(self, cmd, body):
        hdr = smb2_hdr(cmd, self.mid, self.tid, self.sid); self.mid += 1
        return self._xact(hdr + body)

    def disconnect(self):
        try: self.sock.close()
        except: pass
        self.state = 'DISCONNECTED'


# ─── Stateful Grammar: Valid SMB State Transitions ────────────────────────────

# Valid operations per state
STATE_OPS = {
    'FILE_OPEN': [CMD_WRITE, CMD_READ, CMD_LOCK, CMD_IOCTL, CMD_QUERY_INFO,
                  CMD_SET_INFO, CMD_FLUSH, CMD_CLOSE, CMD_QUERY_DIRECTORY],
    'TREE': [CMD_CREATE, CMD_TREE_DISCONNECT],
    'SESSION': [CMD_TREE_CONNECT, CMD_LOGOFF],
}


def parallel_session_race(n_conns=4, target_file='fuzz_race'):
    """True parallel: N raw TCP connections racing on same file.
    No serialization — each socket operates independently."""
    conns = []
    for _ in range(n_conns):
        c = RawSmb2()
        c.connect()
        c.negotiate()
        c.session_setup_ntlmssp()
        c.tree_connect()
        c.create(target_file)
        conns.append(c)

    def worker(conn, ops):
        for op in ops:
            if op == 'write':
                conn.write(os.urandom(4096), random.randint(0, 0xFFFF))
            elif op == 'lock':
                conn.lock(random.randint(0, 0xFFF), random.randint(1, 0xFFF))
            elif op == 'unlock':
                conn.lock(0, 0xFFF, flags=0x20)
            elif op == 'close':
                conn.close()
            elif op == 'disconnect':
                conn.disconnect()

    # Generate random op sequences
    ops_per_conn = []
    for _ in range(n_conns):
        ops = [random.choice(['write', 'write', 'lock', 'unlock', 'write'])
               for _ in range(10)]
        # Last connection gets disconnect (triggers oplock break UAF pattern)
        ops_per_conn.append(ops)
    ops_per_conn[-1].append('disconnect')

    # Launch all in parallel — TRUE concurrency
    threads = [threading.Thread(target=worker, args=(c, ops))
               for c, ops in zip(conns, ops_per_conn)]
    for t in threads: t.start()
    for t in threads: t.join()

    # Cleanup survivors
    for c in conns:
        try: c.disconnect()
        except: pass

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


class DfReader:
    """Reads kcov_dataflow buffer and extracts (PC, ret_value) pairs."""
    def __init__(self, df):
        self.df = df

    def get_ret_values(self):
        """Returns list of (pc, ret_value) from last operation."""
        self.df.disable()
        words = self.df.read_words()
        rets = []
        pos = 0
        while pos + 3 <= len(words):
            hdr, pc, meta = words[pos], words[pos+1], words[pos+2]
            nf = (hdr >> 24) & 0xF
            if not nf: nf = 1
            rt = (hdr >> 28) & 0xF
            if rt == 0xF and pos + 3 < len(words):
                val = words[pos + 3]
                rets.append((pc, val))
            pos += 3 + nf
        return rets


# ─── 1. Binary Search Boundaries ─────────────────────────────────────────────

def binary_search_boundary(do_write_fn, field_name, low, high, df):
    """Find exact value where ret transitions from 0 (success) to error.
    do_write_fn(value) → performs write with that field value.
    Returns (last_success, first_failure) boundary."""
    # Verify low succeeds and high fails
    df.enable()
    do_write_fn(low)
    rets_low = DfReader(df).get_ret_values()
    has_success_low = any(v == 0 for _, v in rets_low)

    df.enable()
    do_write_fn(high)
    rets_high = DfReader(df).get_ret_values()
    has_success_high = any(v == 0 for _, v in rets_high)

    if not has_success_low or has_success_high:
        return None  # Can't binary search (both succeed or both fail)

    # Binary search
    while high - low > 1:
        mid = (low + high) // 2
        df.enable()
        do_write_fn(mid)
        rets = DfReader(df).get_ret_values()
        if any(v == 0 for _, v in rets):
            low = mid  # still succeeds
        else:
            high = mid  # fails
    return (low, high)


def run_boundary_search(fpath, df):
    """Find boundaries for Length and Offset fields on CIFS-mounted write."""
    results = {}

    # Length boundary
    def write_len(length):
        try:
            fd = os.open(fpath, os.O_WRONLY | os.O_CREAT, 0o666)
            os.write(fd, b'X' * min(length, 65536))
            os.close(fd)
        except: pass

    boundary = binary_search_boundary(write_len, 'Length', 1, 0x800000, df)
    if boundary:
        results['Length'] = boundary

    # Offset boundary
    def write_offset(offset):
        try:
            fd = os.open(fpath, os.O_WRONLY | os.O_CREAT, 0o666)
            os.lseek(fd, offset, 0)
            os.write(fd, b'X' * 64)
            os.close(fd)
        except: pass

    boundary = binary_search_boundary(write_offset, 'Offset', 0, 0x7FFFFFFF, df)
    if boundary:
        results['Offset'] = boundary

    return results


# ─── 2. Two-Socket Race ──────────────────────────────────────────────────────

def smb2_hdr(cmd, mid, tid=0, sid=0):
    h = bytearray(64)
    h[0:4] = b'\xfeSMB'
    struct.pack_into('<H', h, 4, 64)
    struct.pack_into('<H', h, 6, 1)
    struct.pack_into('<H', h, 12, cmd)
    struct.pack_into('<H', h, 14, 31)
    struct.pack_into('<Q', h, 24, mid)
    struct.pack_into('<I', h, 36, tid)
    struct.pack_into('<Q', h, 40, sid)
    return bytes(h)


def _send_pdu(sock, pdu):
    try:
        sock.sendall(struct.pack('>I', len(pdu)) + pdu)
    except: pass


def _negotiate_auth(sock):
    """Negotiate + session setup (guest) on a socket. Returns (sid, tid, mid)."""
    mid = 0
    # NEGOTIATE
    body = struct.pack('<HHHH', 36, 1, 1, 0) + struct.pack('<I', 0) + b'\x00'*16
    body += struct.pack('<IHH', 0, 0, 0) + struct.pack('<H', 0x0300)
    pdu = smb2_hdr(0, mid) + body; mid += 1
    _send_pdu(sock, pdu)
    sock.recv(4096)

    # SESSION_SETUP 1
    ntlm = b'NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2' + b'\x00'*16
    hdr = smb2_hdr(1, mid); mid += 1
    body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
    body += struct.pack('<HH', 88, len(ntlm)) + struct.pack('<Q', 0) + ntlm
    _send_pdu(sock, hdr + body)
    resp = sock.recv(4096)
    sid = struct.unpack_from('<Q', resp, 4+40)[0] if len(resp) > 48 else 0

    # SESSION_SETUP 2 (guest user)
    auth = bytearray(128)
    auth[0:12] = b'NTLMSSP\x00\x03\x00\x00\x00'
    struct.pack_into('<I', auth, 60, 0xe2088215)
    off = 72
    struct.pack_into('<HHI', auth, 12, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 20, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 28, 0, 0, off)
    user = b'g\x00u\x00e\x00s\x00t\x00'
    struct.pack_into('<HHI', auth, 36, len(user), len(user), off)
    auth[off:off+len(user)] = user; off += len(user)
    struct.pack_into('<HHI', auth, 44, 0, 0, off)
    struct.pack_into('<HHI', auth, 52, 0, 0, off)

    hdr = smb2_hdr(1, mid, sid=sid); mid += 1
    body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
    body += struct.pack('<HH', 88, off) + struct.pack('<Q', 0) + bytes(auth[:off])
    _send_pdu(sock, hdr + body)
    resp = sock.recv(4096)
    if len(resp) > 48:
        sid = struct.unpack_from('<Q', resp, 4+40)[0]

    # TREE_CONNECT
    path = '\\\\127.0.0.1\\share'.encode('utf-16-le')
    hdr = smb2_hdr(3, mid, sid=sid); mid += 1
    body = struct.pack('<HHHH', 9, 0, 72, len(path)) + path
    _send_pdu(sock, hdr + body)
    resp = sock.recv(4096)
    tid = struct.unpack_from('<I', resp, 4+36)[0] if len(resp) > 44 else 0

    return sid, tid, mid


def two_socket_race(df, n_rounds=20):
    """Socket A writes continuously. Socket B disconnects mid-write.
    Targets UAF when fp->conn is accessed after disconnect."""
    bugs_found = 0

    for _ in range(n_rounds):
        try:
            # Socket A: connect + auth + create
            sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sa.settimeout(2)
            sa.connect(('127.0.0.1', 445))
            sid_a, tid_a, mid_a = _negotiate_auth(sa)

            # Socket B: connect + auth + open SAME file
            sb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sb.settimeout(2)
            sb.connect(('127.0.0.1', 445))
            sid_b, tid_b, mid_b = _negotiate_auth(sb)

            # Both CREATE same file
            fname = b'r\x00a\x00c\x00e\x00'
            for s, sid, tid, mid in [(sa, sid_a, tid_a, mid_a), (sb, sid_b, tid_b, mid_b)]:
                hdr = smb2_hdr(5, mid, tid, sid)
                body = struct.pack('<HBB', 57, 0, 0) + struct.pack('<I', 0)
                body += struct.pack('<QQ', 0, 0) + struct.pack('<IIII', 0x12019F, 0x80, 0x07, 0x05)
                body += struct.pack('<I', 0x40) + struct.pack('<HH', 120, len(fname))
                body += struct.pack('<II', 0, 0) + fname
                _send_pdu(s, hdr + body)
                s.recv(4096)

            # Race: A writes repeatedly, B disconnects mid-write
            df.enable()
            write_data = os.urandom(4096)

            def writer():
                for i in range(10):
                    hdr = smb2_hdr(9, mid_a + i, tid_a, sid_a)
                    body = struct.pack('<HH', 49, 112) + struct.pack('<I', len(write_data))
                    body += struct.pack('<Q', i * 4096)
                    body += b'\x00' * 16  # file_id (invalid but triggers lookup)
                    body += struct.pack('<IIHHI', 0, 0, 0, 0, 0) + b'\x00' + write_data
                    _send_pdu(sa, hdr + body)
                    time.sleep(0.001)

            def disconnector():
                time.sleep(0.005)  # disconnect mid-write
                sb.close()

            t1 = threading.Thread(target=writer)
            t2 = threading.Thread(target=disconnector)
            t1.start(); t2.start()
            t1.join(); t2.join()
            df.disable()

            try: sa.close()
            except: pass
        except Exception:
            pass

    return bugs_found


# ─── 3. Anomaly Detection ────────────────────────────────────────────────────

class AnomalyDetector:
    """Tracks (PC, max_successful_value). Flags when ret=0 for value > 2× max."""

    def __init__(self):
        self.max_success = {}  # pc → max value that returned 0
        self.anomalies = []

    def check(self, rets, context=''):
        """Check ret values for anomalies. rets = [(pc, ret_value), ...]"""
        for pc, val in rets:
            if val == 0:
                # Success — but is it anomalous?
                prev_max = self.max_success.get(pc, 0)
                if prev_max > 0 and val == 0:
                    # This is a "normal success" — track the context value
                    pass
            # We need the ARGUMENT that caused ret=0, not the ret itself
            # This requires correlating entry records with return records

    def check_with_args(self, entries, returns):
        """entries = [(pc, arg_value)], returns = [(pc, ret_value)]
        Flag when arg_value that gets ret=0 is > 2× previous max for that PC."""
        for pc, ret_val in returns:
            if ret_val != 0:
                continue
            # Find corresponding entry with same PC
            for epc, arg_val in entries:
                if epc == pc and arg_val > 0:
                    prev_max = self.max_success.get(pc, 0)
                    if prev_max > 0 and arg_val > prev_max * 2:
                        self.anomalies.append({
                            'pc': pc, 'arg': arg_val,
                            'prev_max': prev_max, 'ratio': arg_val / prev_max
                        })
                    self.max_success[pc] = max(prev_max, arg_val)
                    break

    def report(self):
        if self.anomalies:
            print(f"  [!] {len(self.anomalies)} anomalies: ret=0 for values > 2× previous max")
            for a in self.anomalies[:5]:
                print(f"      PC=0x{a['pc']:x} arg=0x{a['arg']:x} (prev_max=0x{a['prev_max']:x}, {a['ratio']:.1f}×)")
        return self.anomalies


# ─── 4. Stateful Sequence Learning ───────────────────────────────────────────

class SequenceLearner:
    """Tracks which operation sequences reach the deepest PCs.
    Replays best sequences with mutations."""

    def __init__(self):
        self.sequences = []  # [(depth_score, ops_list)]
        self.best_ops = []

    def record(self, ops, pcs_reached):
        """Record a sequence and how deep it went."""
        # Depth = number of unique PCs in ksmbd range
        ksmbd_pcs = [pc for pc in pcs_reached if 0xffffffff80000000 <= pc <= 0xffffffffffffffff]
        depth = len(set(ksmbd_pcs))
        self.sequences.append((depth, ops[:]))
        self.sequences.sort(key=lambda x: -x[0])
        self.sequences = self.sequences[:32]  # keep top 32
        if self.sequences:
            self.best_ops = self.sequences[0][1]

    def get_mutations(self, n=5):
        """Return mutated versions of the best sequence."""
        if not self.best_ops:
            return []
        import random
        mutations = []
        for _ in range(n):
            ops = self.best_ops[:]
            # Mutate: swap two ops, duplicate one, or change a value
            mut_type = random.randint(0, 3)
            if mut_type == 0 and len(ops) > 1:
                i, j = random.sample(range(len(ops)), 2)
                ops[i], ops[j] = ops[j], ops[i]
            elif mut_type == 1 and ops:
                ops.append(random.choice(ops))
            elif mut_type == 2 and ops:
                idx = random.randint(0, len(ops) - 1)
                op = list(ops[idx])
                if len(op) > 1 and isinstance(op[1], int):
                    op[1] ^= random.randint(1, 0xFF)
                ops[idx] = tuple(op)
            elif mut_type == 3 and len(ops) > 1:
                ops.pop(random.randint(0, len(ops) - 1))
            mutations.append(ops)
        return mutations

    def report(self):
        if self.sequences:
            best_depth = self.sequences[0][0]
            print(f"  [seq] Best depth: {best_depth} PCs, {len(self.sequences)} sequences tracked")


# ─── Public API ───────────────────────────────────────────────────────────────

# Persistent state across rounds
_anomaly_detector = AnomalyDetector()
_sequence_learner = SequenceLearner()


def run_sharp_analysis(df, fpath, shared_vpool, all_features):
    """Run all sharp analysis. Called per-round after snipers."""
    results = {}

    # 1. Binary search boundaries
    boundaries = run_boundary_search(fpath, df)
    if boundaries:
        results['boundaries'] = boundaries
        for field, (lo, hi) in boundaries.items():
            print(f"  [boundary] {field}: success={lo} → fail={hi}")
            # Add boundary values to pool
            for v in [lo, hi, lo-1, hi+1, lo//2, hi*2]:
                if 0 < v < 0x100000000:
                    try: shared_vpool.append(v)
                    except: pass

    # 2. Two-socket race
    two_socket_race(df, n_rounds=10)

    # 3. Anomaly report
    _anomaly_detector.report()

    # 4. Sequence learning report
    _sequence_learner.report()

    return results


def record_operation(ops, pcs):
    """Called from worker to record operation sequence + PCs reached."""
    _sequence_learner.record(ops, pcs)


def check_anomaly(entries, returns):
    """Called from worker to check for anomalous ret=0."""
    _anomaly_detector.check_with_args(entries, returns)


# ─── 5. Logic Bug Detection (Trust Boundary Analysis) ─────────────────────────

class TrustBoundaryChecker:
    """Detects logic bugs where operations succeed that shouldn't.
    
    Patterns detected:
    1. Permission bypass: WRITE succeeds after DENY ACE set
    2. State confusion: operation succeeds after file CLOSED
    3. Unexpected success: ret=0 for operation that previously always failed
    4. Lock bypass: WRITE succeeds at locked offset from another session
    """

    def __init__(self):
        self.op_history = []  # [(op_name, offset, result)]
        self.denied_ranges = []  # [(offset, length)] where DENY was set
        self.closed_fids = set()
        self.locked_ranges = []  # [(offset, length, session_id)]
        self.findings = []

    def record_op(self, op_name, offset, length, result, fid=None, session_id=None):
        """Record an operation and check for logic bugs."""
        self.op_history.append((op_name, offset, result))

        # Check 1: WRITE succeeds at denied range
        if op_name == 'WRITE' and result == 0:
            for d_off, d_len in self.denied_ranges:
                if offset >= d_off and offset < d_off + d_len:
                    self.findings.append({
                        'type': 'PERMISSION_BYPASS',
                        'detail': f'WRITE succeeded at offset {offset} which has DENY ACE',
                        'severity': 'CRITICAL'
                    })

        # Check 2: Operation succeeds on closed file
        if fid and fid in self.closed_fids and result == 0:
            self.findings.append({
                'type': 'USE_AFTER_CLOSE',
                'detail': f'{op_name} succeeded on closed fid={fid.hex()[:8]}',
                'severity': 'CRITICAL'
            })

        # Check 3: WRITE succeeds at locked range from different session
        if op_name == 'WRITE' and result == 0 and session_id:
            for l_off, l_len, l_sid in self.locked_ranges:
                if l_sid != session_id and offset >= l_off and offset < l_off + l_len:
                    self.findings.append({
                        'type': 'LOCK_BYPASS',
                        'detail': f'WRITE at {offset} bypassed lock held by session {l_sid}',
                        'severity': 'HIGH'
                    })

    def record_deny(self, offset, length):
        self.denied_ranges.append((offset, length))

    def record_close(self, fid):
        if fid: self.closed_fids.add(fid)

    def record_lock(self, offset, length, session_id):
        self.locked_ranges.append((offset, length, session_id))

    def report(self):
        if self.findings:
            print(f"  [!] LOGIC BUGS: {len(self.findings)} trust boundary violations!")
            for f in self.findings[:5]:
                print(f"      [{f['severity']}] {f['type']}: {f['detail']}")
        return self.findings


_trust_checker = TrustBoundaryChecker()


def check_trust_boundary(op_name, offset, length, result, fid=None, session_id=None):
    """Called from worker after each operation to check for logic bugs."""
    _trust_checker.record_op(op_name, offset, length, result, fid, session_id)
