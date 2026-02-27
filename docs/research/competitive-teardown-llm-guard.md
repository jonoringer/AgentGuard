# Competitive Teardown: LLM Guard

## What it does well
- Broad scanner model for both input and output.
- Practical security scanner packaging.
- Extensible defense strategy around content and data controls.

## Gaps we must close for parity/advantage
- Pluggable scanner architecture with consistent detector contracts.
- Expanded scanner categories beyond regex-only matching.
- Clear detector quality metrics (precision/recall, false-positive rates).

## Build requirements derived
1. Introduce detector interface with normalized findings and severities.
2. Add scanner families: prompt, SQLi, code injection, exfiltration, output safety.
3. Add detector benchmarking harness and tuning workflow.

## Acceptance criteria
- Each detector emits `{rule, passed, severity, message}` into a unified pipeline.
- Final decision score uses weighted detector output.
- Detection tests include known attack corpora.
