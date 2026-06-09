# Cross-version relocation: measured baseline (control)

This is the control measurement for the cross-version fingerprinting initiative. Every later phase
(ensemble, RTTI, shared analysis model, global alignment) is judged against these numbers: coverage must
not regress and the false-positive floor must hold or improve. Reproduce with the `--ignored` harness and
the generation bench named below; the client corpus is local (copyrighted Nexon clients, not
redistributable).

## Corpus

The full GMS unprotected lineage at `X:\Client_Unpacked`, 12 builds spanning several real major
refactors: v61.1, v62.1, v68.1, v72.1, v83.1, v84.1, v88.1, v91.1, v95.1, v95.5, v100.1, v111.1. All are
x86 / PE32 (`Machine=0x014C`). Themida/VMProtect builds (v116/v117/v126/v131) are statically
unanalyzable and excluded.

## Relocation sweep (release, ~72s)

`cargo test -p maple-core --release cross_version_relocation_coverage_and_false_positive_sweep -- --ignored --nocapture`

Reference v83, headline round-trip target v95.1 (the known class refactor). Round-trip back to v83 is the
independent wrong-address check.

| anchor | made | resolved@v95.1 | valid | id-sim | rt P/F/inc | FP | id<0.30 |
|--------|-----:|----:|----:|----:|:--:|:--:|----:|
| string | 35 | 25 | 20 | 0.42 | 3/0/22 | 0% | 8 |
| import | 8 | 1 | 1 | 1.00 | 1/0/0 | 0% | 0 |
| caller | 1 | 0 | 0 | n/a | 0/0/0 | n/a | 0 |
| vtable | 177 | 3 | 2 | 0.64 | 2/0/1 | 0% | 0 |

- **False-positive floor = 0**: zero conclusive round-trip failures on any anchor. This is the bar.
- vtable detail: 3 structural, 0 constructor-grounded, 174 declined (installer present on 2 of 177 made).
- string corroboration of the 25 resolved: 0 share a second independent string; 25 rest on the single
  anchor string, of which 8 also have id<0.30 (the wrong-address suspects the `string_relocation_confirmed`
  gate caps at C).

### String reach across the lineage (resolved / validated, of 35 v83 anchors)

v61 43% · v62 49% · v68 66% · v72 66% · **v83 100%** · v84 100% · v88 97% · v91 97% · **v95.1 71%** ·
v95.5 71% · v100 69% · v111 66%. Coverage decays symmetrically away from the reference and drops at the
v95 break (97% -> 71%).

### Vtable widest-path chain reach (of 25 subsampled methods)

v61 12% · v68 16% · **v83 32%** · v84 24% · v88 24% · v91 24% · **v95.1 0%** · v95.5 0% · v100 0% ·
v111 0%. The structural matcher carries within the v83-v91 lineage and **collapses to 0% at v95.1 and
beyond**. This is the v95 class refactor the structural fingerprint cannot bridge.

### RTTI finding (Phase 3, investigated and declined on data)

The re-audit proposed RTTI class-name grounding as the highest-value bridge for exactly that v95 gap. A
reverse-walk probe (`vtable::tests::rtti_is_sparse_and_exception_only_not_a_general_anchor`) measured the
reality: v83's mapped image contains only **~16 RTTI type descriptors, every one an exception / error /
security framework class** (`_com_error`, `ZException`, `CMSException`, `CTerminateException`,
`CDisconnectException`, `CPatchException`, `CSecurity*`, the std exception types). The gameplay classes a
user actually relocates (`CWvsContext`, `CUser`, packet handlers) carry **no RTTI**, because the client is
built `/GR-` except where C++ exception handling forces it. The locator chain is genuinely navigable where
it exists (the probe resolves com_error's vtable[-1] -> COL -> TypeDescriptor), so this is not a reader
bug. RTTI therefore cannot bridge the v95 break for the targets that matter, and the audit's "RTTI is the
highest-value vtable anchor" does not hold for this corpus. **The real cross-v95 bridge is the ensemble
plus graph alignment (Phases 4 and 7)**, which relocate a method with no content anchor by its position in
the matched call/vtable graph. The probe is kept so a future, RTTI-rich corpus would re-open the question.

## Generation cost (criterion bench, synthetic decodable module)

`cargo bench -p maple-core --bench generate`

Single-build byte path vs the two-build relocation path, at two code sizes. Real client `.text` is
~7-12 MiB; cost is linear in code size. Measured on `main` (773eefd).

| code size | byte path | relocation path |
|-----------|----------:|----------------:|
| 256 KiB | 5.6 ms | 134 ms |
| 1 MiB | 22.8 ms | 532 ms |

These supersede the original Phase 0 figures (10.1 ms / 43.0 ms for the relocation path). That table was
measured before the Phase 4 ensemble and never refreshed, so it read the cost of the old first-success
fallback chain (stop at the first anchor that fires, usually the string). The ensemble now runs **every**
applicable anchor on every relocation to take the cross-anchor vote, so the relocation path costs several
times the first-success path; the byte path is unchanged. The increase is the ensemble, not the shared
analysis model: with the model (773eefd) the relocation path is 134 ms, and a pre-model build (6fbebd1)
measured 128 ms, well within the noise of these pseudo-random runs.

The synthetic module is seeded pseudo-random decodable filler, a worst case for the per-byte (encoding
prefilter) and linear-decode (fingerprint boundaries) scans, so this overstates real per-relocation cost
(real `.text` decodes far more cheaply). On the real corpus the string pass alone (make_string_anchor over
~49.7k v83 entries, each a whole-image scan) took 48s of the 72s sweep: the hot path a shared analysis
model queried by every anchor would cut, when generation speed is the priority.

## Ensemble result (Phase 4)

`cargo test -p maple-core --release ensemble_relocation_holds_the_fp_floor_on_real_gms -- --ignored`

The first-success fallback chain is replaced by a cross-anchor vote: every applicable anchor runs, channels
that land on the same function corroborate, and a channel that lands elsewhere without being outvoted caps
the result to a candidate. Measured over the string-anchorable v83 functions, relocating v83 -> v95.1: **13
relocated, 3 confident, 2 conflict-capped, and confident round-trip 3 pass / 0 fail**. The two conflict
caps are the new false-positive guard firing (independent channels disagreed, so the result was demoted to
a candidate rather than shipped confidently), and the confident results still round-trip with zero wrong
addresses. The chosen landing is always one an anchor produced, so the ensemble can only decline confidence
or pick among agreeing results, never invent an address.

## Rare-constant channel (Phase 5)

A seventh ensemble channel anchors a function by a rare immediate it uses (a value that occurs exactly
once in the code, measured by byte-frequency so it stays O(code) fast), Diaphora's strongest non-string
heuristic. Measured on the v83 sample: with the literal floor at 0x10000 it found **0** anchorable
functions (the game's distinctive constants, packet opcodes and the like, are smaller); lowering the
floor to 0x100 (the exactly-once test, not magnitude, enforces distinctiveness) found **1 made / 0
resolved at v95.1, 0 false positives**. So like the import (8/1) and caller (1/0) channels it is a safe,
sparse contributor on this corpus, the string and vtable channels carry coverage, while the constant
channel adds occasional reach and an independent corroboration/conflict vote in the ensemble at zero FP.
It is correct, fast, and declines on ambiguity; it would matter more on a corpus richer in rare literals.

## Graph alignment (Phase 7)

`cargo test -p maple-core --release graph_alignment_propagates_beyond_seeds_and_is_reverse_consistent -- --ignored`

The seed-and-propagate call-graph aligner (`sigmaker/graph.rs`) relocates functions no content anchor
pins, by their position in the matched graph: seed with the 1:1 string anchors between two builds, then
propagate by neighbour consensus (a function commits only when at least two independent already-matched
neighbours agree on the same candidate, it is the strict unique maximum, and the match is mutual-best).
The honesty check is an INDEPENDENT reverse alignment; a forward match `a -> b` whose target relocates
back to a different function is a confirmed wrong address.

Measured v83 reference to later builds (17 string seeds among v83's call-graph functions):

| hop | seeds | propagated beyond seeds | reverse-consistent | confirmed wrong (FP) |
|-----|------:|------------------------:|-------------------:|---------------------:|
| v83 -> v84   | 17 | 1187 | 1187 / 1187 | 0 |
| v83 -> v88   | 16 |  743 |  743 /  743 | 0 |
| v83 -> v91   | 16 |   66 |   66 /   66 | 0 |
| v83 -> v95.1 | 12 |    0 |     n/a     | 0 |

Graph position alone relocates 1187 functions at one recompile, every one reverse-round-trip consistent
and none contradicted. The reach decays with version distance, the seeds' call relationships drift across
more recompiles so fewer functions keep a two-neighbour consensus, and collapses at the v95 refactor where
only 12 string seeds survive, too sparse to form any consensus, so the aligner commits nothing and
declines. The false-positive floor holds at zero on every hop, including the major break. The v95 reach is
seed-density-limited, not a mechanism failure; a denser cross-refactor seed source would extend it, but
none exists on this corpus (import 1, constant 1, vtable 0 resolve across the v95 break).

## Gates every later phase must satisfy

1. Conclusive round-trip false positives stay at 0 on import/caller/vtable (the floor above).
2. String/vtable/chain coverage at each build does not regress versus this table.
3. The golden snapshot stays byte-stable unless a change intentionally alters output.
4. Generation cost: the byte path stays flat and the relocation path stays at or below the ensemble
   figures above (134 ms / 532 ms), within run-to-run noise. A change must not push it materially higher
   without a stated reason; re-pointing the anchors to one shared, queried model is the lever that would
   bring it down. (The original "must fall" target assumed the dead Phase 0 first-success numbers and is
   not a regression bar against the ensemble.)
