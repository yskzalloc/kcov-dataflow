#!/usr/bin/env python3
"""Parse a gfuzz campaign log into ksmbd/10rounds.md: per-round saturation stats +
sweet-spot analysis for ksmbd security-hardening triage. Re-runnable at any time."""
import re, sys, collections

LOG = sys.argv[1] if len(sys.argv) > 1 else "/home/debian-sid/ksmbdzzer.log"
OUT = "/home/debian-sid/kcov-dataflow/ksmbd/10rounds.md"

P2 = re.compile(r'\[P2\]\s+(?P<pfx>\w+)\s+(?P=pfx)_(?P<name>[^@]+)@[\d.]+:\s+(?P<sec>\d+)s\s+execs=(?P<execs>\d+)\s+'
                r'ft0=(?P<ft0>\d+)→(?P<ft>\d+)\s+\(Δ\+?(?P<delta>-?\d+)\)\s+\[(?P<flags>[^\]]+)\]\s+\((?P<sat>[^)]+)\)')
RH  = re.compile(r'--- Round (\d+)/(\d+) ---')
CORP= re.compile(r'\[corpus\]\s+(\d+)\s+accumulated')
FF  = re.compile(r'\[feed-forward\]\s+(\d+)\s+grains.*carried\):\s*(.*)')
DEAD= re.compile(r'\[!\]\s+(?P<pfx>\w+)\s+(?P=pfx)_(?P<name>[^@]+)@.*0 executions')
BUG = re.compile(r'(KASAN|BUG:|Oops|general protection|recursive locking|WARNING:|UBSAN|list_\w*corrupt)')

rounds = []           # list of dict(round, total_rounds, corpus, ff, elems=[], dead=[])
cur = None
bugs = []
for ln in open(LOG, errors='replace'):
    m = RH.search(ln)
    if m:
        cur = dict(round=int(m.group(1)), total=int(m.group(2)), corpus=None, ff=None, elems=[], dead=[])
        rounds.append(cur); continue
    if cur is None:
        continue
    m = P2.search(ln)
    if m:
        d = m.groupdict()
        cur['elems'].append(dict(name=d['name'], sec=int(d['sec']), execs=int(d['execs']),
                                 ft0=int(d['ft0']), ft=int(d['ft']), delta=int(d['delta']),
                                 aligned='ALIGNED' in d['flags'], productive='PRODUCTIVE' in d['flags'],
                                 saturated=d['sat'].strip()=='SATURATED')); continue
    m = DEAD.search(ln)
    if m: cur['dead'].append(m.group('name')); continue
    m = CORP.search(ln)
    if m: cur['corpus'] = int(m.group(1)); continue
    m = FF.search(ln)
    if m: cur['ff'] = (int(m.group(1)), m.group(2).strip()); continue
    if BUG.search(ln): bugs.append(ln.strip())

# ---- aggregate across rounds (exclude combo_ synthetic elements from grain stats) ----
def is_grain(e): return not e['name'].startswith('combo_')
peak_ft   = collections.defaultdict(int)     # deepest coverage reached per grain
peak_delta= collections.defaultdict(int)     # best mutation gain over baseline
ft0_first = {}; ft0_last = {}                 # feed-forward: ft0 first vs last seen
sat_count = collections.defaultdict(int); seen_count = collections.defaultdict(int)
for r in rounds:
    for e in r['elems']:
        if not is_grain(e): continue
        n = e['name']
        peak_ft[n]    = max(peak_ft[n], e['ft'])
        peak_delta[n] = max(peak_delta[n], e['delta'])
        if n not in ft0_first: ft0_first[n] = e['ft0']
        ft0_last[n] = e['ft0']
        seen_count[n] += 1
        if e['saturated']: sat_count[n] += 1

def bar(v, vmax, w=24):
    return '█'*int(round(w*v/vmax)) if vmax else ''

L = []
W = L.append
W("# ksmbdzzer — 10-round procedure-fuzz campaign statistics\n")
W("Coverage metric **ft** = kcov-dataflow features (kernel PC ^ arg/ret value) reached by a grain "
  "element. **ft0** = the element's *starting* coverage (its replayed feed-forward corpus); "
  "**ft** = coverage after saturation; **Δ = ft − ft0** = new code the round's mutation found beyond "
  "the carried corpus. A grain is ALIGNED if ft≥100 (reaches deep), PRODUCTIVE if the mutation beat "
  "its own baseline. Rows are per-grain; `combo_*` (P3 concurrent pairs) are summarized separately.\n")
if bugs:
    W(f"> ⚠️ **{len(bugs)} kernel bug line(s) detected — see the Bugs section and `findings/`.**\n")
W(f"Rounds parsed: **{len(rounds)}**"
  + (f" / {rounds[0]['total']} planned" if rounds else "") + "\n")

# ---- per-round ----
for r in rounds:
    W(f"\n## Round {r['round']}/{r.get('total','?')}\n")
    line = []
    if r['corpus'] is not None: line.append(f"corpus **{r['corpus']}** carried inputs")
    grains = [e for e in r['elems'] if is_grain(e)]
    if grains:
        nsat = sum(e['saturated'] for e in grains)
        naln = sum(e['aligned'] for e in grains)
        nprod= sum(e['productive'] for e in grains)
        line.append(f"{len(grains)} grains ({naln} aligned, {nprod} productive, {nsat} saturated)")
    if r['dead']: line.append(f"{len(r['dead'])} dead (0-exec): {', '.join(r['dead'][:6])}")
    W("- " + " · ".join(line) + "\n")
    if r['ff']:
        W(f"- **feed-forward:** {r['ff'][0]} grains started deeper — {r['ff'][1]}\n")
    if grains:
        W("\n| grain | ft0 | ft | Δ | aligned | productive | sat | execs |\n")
        W("|---|--:|--:|--:|:-:|:-:|:-:|--:|\n")
        for e in sorted(grains, key=lambda x: -x['ft']):
            W(f"| {e['name']} | {e['ft0']} | {e['ft']} | {e['delta']:+} | "
              f"{'✓' if e['aligned'] else '·'} | {'✓' if e['productive'] else '·'} | "
              f"{'✓' if e['saturated'] else '·'} | {e['execs']} |\n")
    combos = [e for e in r['elems'] if not is_grain(e)]
    if combos:
        best = sorted(combos, key=lambda x: -x['ft'])[:5]
        W("\n*P3 combos (concurrent pairs):* " +
          ", ".join(f"{c['name'].replace('combo_','')} ft={c['ft']}(Δ{c['delta']:+})" for c in best) + "\n")

# ---- SWEET SPOTS ----
W("\n---\n\n# Sweet spots — where to focus ksmbd hardening\n")
W("These rankings turn the campaign into a triage list: which SMB procedures the fuzzer "
  "penetrates deepest and keeps finding new behavior in (review these first), which compound "
  "over rounds (worth long campaigns), and which the fuzzer bounces off (tooling gaps, not "
  "hardening signal).\n")

if peak_ft:
    mx = max(peak_ft.values())
    W("\n## 1. Prime targets — deepest reachable surface (peak ft)\n")
    W("High ft = the procedure exposes a large, mutation-reachable kernel code region → the richest "
      "place for bugs to hide. **Start hardening review here.**\n\n")
    W("| grain | peak ft | best Δ | saturation | depth |\n|---|--:|--:|:-:|:--|\n")
    for n, v in sorted(peak_ft.items(), key=lambda x: -x[1])[:12]:
        satr = f"{sat_count[n]}/{seen_count[n]}"
        W(f"| {n} | {v} | {peak_delta[n]:+} | {satr} | {bar(v, mx)} |\n")

    W("\n## 2. Most fuzzable — biggest new-code gain over baseline (peak Δ)\n")
    W("High Δ = mutation repeatedly finds code *beyond* the carried corpus → an actively-productive "
      "surface. Combined with #1, these are the strongest bug-hunting bets.\n\n")
    mxd = max(peak_delta.values()) or 1
    W("| grain | best Δ | peak ft | |\n|---|--:|--:|:--|\n")
    for n, v in sorted(peak_delta.items(), key=lambda x: -x[1])[:12]:
        W(f"| {n} | {v:+} | {peak_ft[n]} | {bar(max(v,0), mxd)} |\n")

    gains = {n: ft0_last[n]-ft0_first[n] for n in ft0_first if ft0_last[n] > ft0_first[n]+50}
    if gains:
        W("\n## 3. Compounding targets — feed-forward responsive (ft0 growth across rounds)\n")
        W("These grains START each round far deeper than the last because the persistent corpus keeps "
          "unlocking new state → **long multi-round campaigns pay off most here.**\n\n")
        W("| grain | ft0 first→last | growth |\n|---|--:|--:|\n")
        for n, g in sorted(gains.items(), key=lambda x: -x[1])[:12]:
            W(f"| {n} | {ft0_first[n]}→{ft0_last[n]} | +{g} |\n")

    shallow = sorted([n for n in peak_ft if peak_ft[n] < 100], key=lambda n: peak_ft[n])
    flat    = sorted([n for n in peak_delta if peak_ft[n] >= 100 and peak_delta[n] < 100],
                     key=lambda n: peak_delta[n])
    W("\n## 4. Blind spots — fuzzer bounces off (tooling gap, NOT a hardening signal)\n")
    W("Low ceilings mean the *harness* isn't reaching depth (bad prefix / from-scratch parse wall), "
      "not that the code is safe. **Fix the grain before drawing conclusions here.**\n\n")
    W(f"- **Shallow (peak ft<100):** {', '.join(shallow) if shallow else '(none)'}\n")
    W(f"- **Flat (deep but mutation adds nothing, Δ<100):** {', '.join(flat) if flat else '(none)'}\n")
    dead_any = sorted(set(d for r in rounds for d in r['dead']))
    if dead_any:
        W(f"- **Ever died (0-exec / auth failure some round):** {', '.join(dead_any)}\n")

# ---- saturation profile ----
W("\n## 5. Saturation profile per round\n")
W("Saturated = the element stopped finding new paths within its budget (explored its reachable "
  "space). Rising saturation with rising corpus = the campaign is converging.\n\n")
W("| round | corpus | grains | aligned | productive | saturated |\n|--:|--:|--:|--:|--:|--:|\n")
for r in rounds:
    g = [e for e in r['elems'] if is_grain(e)]
    if not g: continue
    W(f"| {r['round']} | {r['corpus'] if r['corpus'] is not None else '?'} | {len(g)} | "
      f"{sum(e['aligned'] for e in g)} | {sum(e['productive'] for e in g)} | "
      f"{sum(e['saturated'] for e in g)} |\n")

# ---- bugs ----
W("\n## 6. Kernel bugs observed\n")
if bugs:
    seen = set()
    for b in bugs:
        key = b[:80]
        if key in seen: continue
        seen.add(key)
        W(f"- `{b[:140]}`\n")
    W("\nFull stack traces saved under `ksmbd/findings/`.\n")
else:
    W("- None in this campaign (no KASAN/BUG/UBSAN/lockdep on the console).\n")

open(OUT, "w").write("".join(L))
print(f"wrote {OUT}: {len(rounds)} rounds, {len(peak_ft)} distinct grains, {len(bugs)} bug lines")
