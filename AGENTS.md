# Instructions for agents

This repository holds the FPSOT signed records and transparency log specification: seals on outbound government records in the ETSI formats of the European list, trusted time stamps, a C2SP transparency log of salted hashes with witnesses and a published policy, offline proofs for readers, monitoring, evidence records for long-term preservation, retention and transfer, and algorithm agility.

- The normative text is in `spec/en/` and `spec/fr/`. Every rule has an ID such as `LOG-001`.
- Follow `skill/SKILL.md` when you write or review code that seals records, adds them to a transparency log, runs a witness or a monitor, verifies a record, or preserves sealed records. The spec text wins on any difference.
- Every page exists in English and in French, with the same file name and the same IDs.
- Terms and abbreviations come from the term base of `fpsot-spec-writing`. Add a missing term there first; `TERMS-NEEDED.md` lists the ones this spec waits for.
- This is a layer 1 specification. It may refer to the layer 0 specifications, to data types, vocabularies, data models, api-restful, testing, security, observability and identity. It never refers to the registry, code or capability specifications, except by topic.
- The observability specification owns OBS-110 to OBS-117. This specification applies them to sealed records by reference and never changes them: the leaf, the hash, the salt, the keys and the witness algorithm stay as OBS sets them.
- Do not name a product in a rule. Name the standard or the capability; products may appear only on the informative page `reference-stack.adoc`.
- Examples and fixtures hold synthetic data only: domains reserved for documentation, example keys, and no record content in a log entry. Run `bash examples/test-examples.sh` after changing an example.
- Do not copy text from ETSI, the European Union, C2SP, the IETF, the Canadian Centre for Cyber Security, the Treasury Board or Québec law. Summarize in your own words and cite the exact version.
- Do not state a legal point as a rule. Points that need a lawyer go in an informative note or in `questions-for-counsel.adoc`, and an article number that nobody checked at the source is marked "to be verified".
- Commits follow Conventional Commits and are signed. Pull requests are squash-merged.
