---
name: fpsot-log
description: Signed records and transparency log rules for FPSOT software. Use when writing or reviewing code that seals outbound government records, takes time stamps, adds records to a transparency log, publishes witness policies, runs a witness, a mirror or a monitor, builds or checks proofs for readers, preserves sealed records with evidence records, or destroys or migrates sealed records.
---

# FPSOT signed records and transparency log

Summary of the FPSOT signed records and transparency log specification. It adds no rules of its own.
The spec text in `spec/` wins on any difference. Each line cites its requirement ID.
"Log" here means a public transparency log of sealed records, not software logs.
The example files are `examples/records-log.tlog-policy`, `examples/sealed-record.tlog-proof` and `examples/seal-manifest.json`; `examples/check-examples.py` checks them.

Each line keeps the strength of its rule: "must" and "must not" are MUST and MUST NOT, "should" and "should not" are SHOULD and SHOULD NOT, "may" is MAY.

Rules name standards and capabilities, never products. Products appear only in `spec/en/reference-stack.adoc`, which is informative.
OBS-110 to OBS-117 belong to the observability specification; this one applies them to sealed records and never changes them.

## Roles and profiles

- State the roles you fill: issuer, log operator, witness, monitor, mirror, verifier, preservation service (LOG-001).
- Each series of records claims `seal`, `seal-log` or `seal-log-preserve` in the deployment inventory; official public records need at least `seal-log`; series that must stay verifiable past the LOG-092 end date of their seal algorithm (for LOG-015 algorithms, past 31 December 2030), or kept permanently, need `seal-log-preserve`; judged by record retention, not the sealing year (LOG-002).
- A conformance claim must not suggest a legal status; it names the jurisdiction and the trust-anchor sets (LOG-003).
- Follow the pinned versions on the overview page (LOG-004); conformance suites check output only, under TST-044 (LOG-005).

## Seals

- Only the Annex I formats of Implementing Regulation (EU) 2026/248 at their pinned versions; no Annex II legacy formats for new seals (LOG-010).
- Format by media type: JSON → JAdES, PDF → PAdES, XML → XAdES, anything else or several files → detached CAdES in ASiC-E; the container may hold only time stamps added before logging (LOG-011).
- JAdES carries `x5c` with the seal chain, signed or unsigned header (LOG-012).
- Level B-LT or higher; B-B and B-T alone do not conform; B-LTA may; a B-LTA augmentation after logging is a new file, and verifiers need the logged original (LOG-013).
- Organizational seal by default (should); a named official's signature only where a law names one (LOG-014).
- ECDSA P-384 with SHA-384 (should), or RSA ≥ 3072 with SHA-384 or stronger; no other seal algorithm, Ed25519 is for log keys only (LOG-015).
- Seal keys in a FIPS 140-3 level 3 or Common Criteria EAL4+ module, under SEC-020 and SEC-023 (LOG-016).
- Publish each trust-anchor set with a name, a stable HTTPS address and a validity period; verifiers trust no other anchor (LOG-017).
- Each seal records its trust-anchor set and assurance level: `tbs` 1–4, `icpg` base/moyen/eleve, `eidas` advanced/qualified (LOG-018).
- Keep a JSON seal manifest per record with `id`, `profile`, `mediaType`, `format`, `formatVersion`, `level`, `signerType`, `algorithm`, `certificateSha256`, `trustAnchorSet`, `assuranceLevel`, `sealedAt`, `timeStampAuthority`, `retentionRule`, `log` and optional `replaces` and `hybridWith`; never the salt, content or personal information (LOG-019).

## Time

- RFC 3161 time stamp from an authority under ETSI EN 319 421 V1.3.1 or an equivalent published policy; EU-qualified when EU effect is wanted (LOG-020).
- List each time-stamp authority in a trust-anchor set; hash requests with SHA-384 or stronger (LOG-021).
- `sealedAt` is the token time, never the local clock; clocks synchronized under OBS-033 (LOG-022).
- Time-stamp at least one checkpoint a day (each checkpoint should), over SHA-384 of the checkpoint text followed by the log signature line, without cosignatures, published beside it (LOG-023).
- Witness cosignature times corroborate; they are never a trusted time stamp (LOG-024).

## Transparency log

- Meet OBS-110, OBS-113, OBS-115 and OBS-117 and apply OBS-116 with its own requirement levels, with sealed records in place of audit records; OBS-114 applies and LOG-041 makes it stricter (LOG-030).
- Each entry is the OBS-111 salted hash: SHA-256 over a random salt of 32 bytes or more, then the exact sealed bytes at the moment of logging, which the issuer keeps and delivers unchanged; one salt per record, kept by the issuer with the record; the issuer, not the log operator, recomputes leaves under OBS-115; nothing else about the record in the log (LOG-031).
- Ed25519 checkpoints under OBS-112 and C2SP tlog-checkpoint v1.1.0; origin `<issuer domain>/<series name>-<year>` (should), the issuer domain replacing the OBS-112 operator domain; an ML-DSA-44 self-cosignature may be added (LOG-032).
- No checkpoint extension lines (LOG-033).
- Keys under OBS-113; the log key differs from every seal key and signs only its checkpoints; a new key per shard (should) (LOG-034).
- New shard each UTC calendar year (an entry belongs to the year it is logged) and before any algorithm change; close it with a witnessed, time-stamped final checkpoint; keep it readable (LOG-035).
- Serve each shard with C2SP tlog-tiles v1.0.0; never prune (LOG-036).
- The issuer arranges that at least one independent mirror keeps every shard, checks consistency and serves it; C2SP tlog-mirror v0.1.0 (should) (LOG-037).
- One issuer per log; writes only from that issuer's authenticated sealing service (LOG-038).

## Witnesses and policy

- Publish a C2SP tlog-policy per shard before its first entry, with the log key, each witness key and one quorum (LOG-040).
- The quorum requires at least two independent public witnesses and at least one accountable domestic witness, a public body of the same country other than the issuer; never `quorum none`; groups `public` and `domestic` joined with `all` (should); at least three public witnesses (should) (LOG-041).
- Witnesses are independent of issuer and log operator, which excludes the operator's own archives function; publish the log operator and each witness operator and contact; check witnesses yearly (LOG-042).
- Witnesses should cosign with ML-DSA-44 and may add Ed25519, an option OBS-114 leaves open (LOG-043).
- Witnesses follow C2SP tlog-witness v1.1.0, check consistency before cosigning, and should serve their latest checkpoint within an hour (LOG-044).
- Never edit a published policy; each version states the first tree size it governs and stays published; verifiers apply the version whose range holds the checkpoint's tree size (LOG-045).
- No proof before the quorum cosigns; the record may go first; state the longest delay in the inventory (LOG-046).

## Proofs and verification

- Deliver a `c2sp.org/tlog-proof@v1` proof with each `seal-log` record, as a `.tlog-proof` file beside it or in an outer bundle that is not logged, never inside the logged bytes (LOG-050).
- Put the raw salt, in canonical base64, in the `extra` line or the outer bundle of LOG-050; verifiers compute SHA-256(salt ‖ sealed bytes), then the leaf and the inclusion proof (LOG-051).
- A proof with the salt goes only to parties entitled to the record; publish it only for public records (LOG-052).
- Verification works offline from published material; the issuer offers an open-source verifier (LOG-053).
- Verifiers report seal, time stamp, log signature, cosignatures and quorum, inclusion and evidence record separately; reject non-canonical base64; seal report per ETSI TS 119 102-2 V1.4.1 (LOG-054).
- Never present a seal image, logo or printed mark as proof (LOG-055).
- Printouts should carry a look-up code and QR code to the sealed original and its proof; no personal information; at least 128 random bits for non-public records (LOG-056).
- RFC 9942 receipts from the same tree may be issued, never in place of the proof (LOG-057).

## Monitoring and incidents

- Keep a register of each sealed record with its manifest, who asked, who approved, and its log entry (LOG-060).
- Run a monitor under another role that alerts on unknown entries, inconsistent checkpoints, unknown keys or certificates, and missing quorums (LOG-061).
- Separate who asks for a seal from who administers the key; second approval above a set volume; two people for key operations (LOG-062).
- Keep and yearly test a plan for key leaks, key-generation flaws and broken algorithms: revoke, close the shard, find, re-seal with a transfer record, notify (LOG-063).
- Record `org.fpsot.log.record.sealed`, `.record.resealed`, `.record.withdrawn`, `.checkpoint.signed`, `.shard.closed`, `.policy.published`, `.key.rotated`, `.alert.raised` with the content of OBS-027; no record content, salt or personal information (LOG-064).

## Preservation

- `seal-log-preserve` records get RFC 4998 or RFC 6283 evidence records over the logged bytes, the proof and the validation data, kept beside the logged original and never embedded in it, before the seal's time-stamp certificate expires (LOG-070).
- Evidence-record hash trees use SHA-384, SHA-512, SHA3-384 or SHA3-512; the log keeps SHA-256 (LOG-071).
- Renew before time-stamp or hash algorithms weaken and at each suite change; review yearly; SLH-DSA or hybrid time stamps once available (should) (LOG-072).
- Verification lifetime equals the retention period; keep all validation data that long (LOG-073).
- Follow ETSI TS 119 511 V1.1.1 and pack archives per ISO 14721:2025 (should) (LOG-074).
- Keep an evidence record of each `seal-log-preserve` shard: final checkpoint, cosignatures, time stamp, policy versions (LOG-075).

## Retention, redaction and transfer

- Meet OBS-100, OBS-102, OBS-103 and OBS-104 and apply OBS-116 with its own requirement levels, for sealed records, salts, manifests and register entries; OBS-101 does not apply (LOG-080).
- Destroy record and salt together in every copy; never remove or change the leaf; the destruction event names shard and index (LOG-081).
- Never change a sealed record: correct with a new record and `replaces`, withdraw with `org.fpsot.log.record.withdrawn`, redact by withdrawing and sealing a redacted copy (LOG-082).
- Format migration or re-sealing keeps an OBS-105 transfer record linking old and new; the new record gets its own entry; keep the old one for its retention (LOG-083).
- Each closed shard is a records series with its own retention rule; keep shards with permanent records permanently (LOG-084).
- No personal information in the log, checkpoints, policies or published proofs; never log an unsalted hash; the privacy impact assessment should cover the log (LOG-085).

## Algorithm agility

- Every seal, time stamp, signature, cosignature and evidence record names its algorithm; algorithms come from configuration; changing one needs no format change (LOG-090).
- Verifiers accept several seals; the manifest's `hybridWith` names the other seal of a hybrid pair; report the pair passed only if both pass, and not verified if one cannot be checked (LOG-091).
- Keep a key and algorithm inventory with end dates, review it yearly, and plan the move to post-quantum on ITSM.40.001 milestones (LOG-092).
- Verifiers accept ML-DSA-44 (`0x06`) and Ed25519 (`0x04`) cosignatures (LOG-093).
