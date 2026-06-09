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

Single-build byte path vs the two-build relocation path (which fires the whole-code-section anchor scans),
at two code sizes. Real client `.text` is ~7-12 MiB; cost is linear in code size.

| code size | byte path | relocation path |
|-----------|----------:|----------------:|
| 256 KiB | 5.7 ms | 10.1 ms |
| 1 MiB | 22.4 ms | 43.0 ms |

On the real corpus the string pass alone (make_string_anchor over ~49.7k v83 entries, each a whole-image
scan) took 48s of the 72s sweep: the F1 hot path the shared analysis model (Phase 2) must cut.

## Gates every later phase must satisfy

1. Conclusive round-trip false positives stay at 0 on import/caller/vtable (the floor above).
2. String/vtable/chain coverage at each build does not regress versus this table.
3. The golden snapshot stays byte-stable unless a change intentionally alters output.
4. Generation cost does not increase; Phase 2 onward should show it falling on this bench.
