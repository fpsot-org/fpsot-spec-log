# Changelog

All notable changes to this specification are listed here.
The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-11

### Added

- Roles, profiles, legal status and conformance LOG-001 to LOG-005: the issuer, log operator, witness, monitor, mirror, verifier and preservation service; the `seal`, `seal-log` and `seal-log-preserve` profiles; no claim of legal status; pinned versions; conformance suites that check output only.
- Seal rules LOG-010 to LOG-019: the formats of Annex I of Implementing Regulation (EU) 2026/248 chosen by media type, the `x5c` header in JAdES, level B-LT or higher, organizational seals by default, ECDSA P-384 with SHA-384 or RSA of 3072 bits or more, keys in certified hardware, published trust-anchor sets, assurance levels and the seal manifest.
- Time-stamp rules LOG-020 to LOG-024: RFC 3161 tokens from an authority under ETSI EN 319 421 V1.3.1 or an equivalent policy, SHA-384 requests, the time of the token in the manifest, daily time stamps over checkpoints, and witness times as corroboration only.
- Transparency log rules LOG-030 to LOG-038, which apply OBS-110 to OBS-117 to sealed records without changing them: a salted hash of the exact sealed bytes, checkpoints without extension lines, yearly shards, the C2SP tlog-tiles interface, an independent mirror and one issuer per log.
- Witness rules LOG-040 to LOG-046: a published C2SP tlog-policy per shard with a quorum of at least two public witnesses and one domestic witness, witness independence, the witness algorithm of OBS-114, C2SP tlog-witness v1.1.0, policy versions and no proof before the quorum.
- Proof and verification rules LOG-050 to LOG-057: a `c2sp.org/tlog-proof@v1` proof with each record, the salt for entitled readers only, offline verification with an open-source verifier, separate results per check, no proof by seal image, look-up codes on printouts, and optional COSE Receipts.
- Monitoring rules LOG-060 to LOG-064, preservation rules LOG-070 to LOG-075 with RFC 4998 or RFC 6283 evidence records at SHA-384 or stronger, retention rules LOG-080 to LOG-085, and agility rules LOG-090 to LOG-093 with a planned hybrid seal.
- Informative pages on the reference stack and on questions for counsel.
- Examples: a witness policy, a proof with real Ed25519 signatures, a seal manifest and a stand-in for the sealed bytes, with a check script and its test, run by the `examples` job of the continuous integration.
- Comparison data with Canada and Québec rows.
- How-to guide that seals and publishes a series of records.

[Unreleased]: https://github.com/fpsot-org/fpsot-spec-log/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fpsot-org/fpsot-spec-log/releases/tag/v0.1.0
