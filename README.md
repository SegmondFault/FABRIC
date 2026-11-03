Whoever you are, you're here very early... As its early, but I didn't want to leave this blank I had a chabot generate the below, cursed at it, and then rewrote it. Mostly. Consider yourself forewarned.

# RELIC

**Reproducible Evidence for Lineage and Integrity of Code**

RELIC exists to make bounded, evidence backed assertions about the **legitimacy, heritage and origin of functions within binaries**.

It combines BSim data, FIDBF records, reproducible provenance and a small supporting layer of machine learning. 

Initial corpus I hope to be nearly every C library, HPC willing. Primarily I'm generating from per lane (arch, os, compiler, optimisation, starsign...)  builds of public available source code via FIDBF-gen, to create a provenance tracked ground truth, though I hope to incorporate some ecological bins from online sources, malicious and otherwise.

## Bounding bounded assertion means

An assertion made through RELIC is limited by:

- the coverage and quality of the corpus;
- the provenance of the submitted data;
- the reproducibility of the analysis;
- the strength of the observed function relationships;
- the confidence and limitations of any model involved.
- Estimations on the distinguishability of a specific or full (fidb) hash (yes they collide - though rarely and usually inconsequentially) and BSIMs

The system should preserve the evidence behind an assertion so that another analyst can inspect it, reproduce it and reach their own conclusion.

## Evidence

RELIC brings together:

- **BSim** objects describing function-level similarity;
- **FIDBF** objects associated with analysed binaries;
- binary and function hashes;
- source and provenance records;
- signed submissions and moderation actions;
- reproducibility evidence;
- supporting machine-learning results.

## Current status

RELIC is an early proof of concept.

The repository currently contains:

- a PostgreSQL 15+ schema;
- application access rules;
- foundational Rust submission types and validation;
- the working schema and implementation plan;
- a root-only server update script.

The API, object-storage integration, import pipeline, matching services and machine-learning components are still to be implemented.

## Design principles

- Assertions must remain traceable to their evidence.
- SHA-256 provides the primary content identity.
- MD5 is retained because I don't want (or know how) to rewrite GHIDRA.
- Binary bytes are not stored.
- Binary and function records are covered by signed batches.
- Independently submitted objects and moderation actions carry their own signatures.
- Sources and provenance are recorded separately.
- FIDBF and BSim data may be absent.
- Provenance supports external reproduction without imposing one universal provenance format.
- Uncertainty and missing evidence must remain visible.

## Repository structure

```text
crates/     Small Rust domain components
database/   PostgreSQL schema and access policy
design/     Working schema and implementation plan
scripts/    Controlled operational scripts
```

## FIDBF submissions

The server treats an FIDBF as an opaque object and does not run Ghidra. The
analyst supplies every FIDBF and associated function column required by the
submission. The Rust domain crate validates hashes, required values and
cross-record binary identity before the future import service persists them.

Automatic extraction from an FIDBF is a deferred stretch goal.

Items shown in parentheses in the implementation plan are stretch goals.

## Contributing

Create a branch for each change and submit it as a pull request into `main`.

```bash
git switch -c feature/short-description

# Make and review the changes

git add .
git commit -m "Describe the change"
git push -u origin feature/short-description
```

Do not commit:

- binary samples;
- credentials or private keys;
- database contents;
- object-storage contents;
- server addresses or personal information.

## Server updates

Approved changes are merged into `main`.

The server updater fetches and fast-forwards the shared checkout at `/srv/relic`. It refuses to run as a non-root user or when the server checkout contains uncommitted changes.

## Licence

RELIC is licensed under the Apache License 2.0. See
[`LICENSE`](LICENSE).
