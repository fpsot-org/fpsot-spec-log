# Terms needed

Entries in the format of `termbase/terms.yaml` of fpsot-spec-writing, for a pull request to the term base.
The pages of this specification already use them.
The French forms marked "to confirm" have no record in the Grand dictionnaire terminologique that the writer could find.

```yaml
  - id: eidas
    kind: abbreviation
    en: {short: "eIDAS", full: "Regulation (EU) No 910/2014 on electronic identification and trust services", definition: "The regulation of the European Union on electronic identification and on trust services, such as signatures, seals and time stamps."}
    fr: {short: "eIDAS", full: "règlement (UE) no 910/2014 sur l'identification électronique et les services de confiance", definition: "Règlement de l'Union européenne sur l'identification électronique et les services de confiance, comme les signatures, les cachets et l'horodatage."}
    source: {name: "EUR-Lex, Regulation (EU) No 910/2014, consolidated text of 2024-05-20 (no GDT record needed for a title)", url: "https://eur-lex.europa.eu/eli/reg/2014/910/2024-05-20/eng", checked: "2026-11-11"}
  - id: etsi
    kind: abbreviation
    en: {short: "ETSI", full: "European Telecommunications Standards Institute", definition: "The European standards body that publishes, among others, the formats and policies of electronic signatures, seals and time stamps."}
    fr: {short: "ETSI", full: "Institut européen des normes de télécommunications", definition: "Organisme européen de normalisation qui publie, entre autres, les formats et les politiques des signatures, des cachets et de l'horodatage électroniques."}
    source: {name: "ETSI (proper name; the French name is the one ETSI uses; TERMIUM Plus not checked)", url: "https://www.etsi.org/", checked: "2026-11-11"}
  - id: tsa
    kind: abbreviation
    en: {short: "TSA", full: "time-stamp authority", definition: "A trusted party that signs a hash together with the time at which it received it."}
    fr: {short: "TSA", full: "autorité d'horodatage", definition: "Tiers de confiance qui signe un condensé avec l'heure à laquelle il l'a reçu."}
    source: {name: "RFC 3161 for the English form; Grand dictionnaire terminologique, autorité d'horodatage, to confirm", url: "https://www.rfc-editor.org/info/rfc3161", checked: "2026-11-11"}
  - id: seal
    kind: term
    en: {full: "seal", definition: "An advanced electronic signature that an organization applies as an organization, to prove that it issued a record and that nobody changed it since."}
    fr: {full: "cachet électronique", definition: "Signature électronique avancée qu'une organisation appose en son propre nom, pour prouver qu'elle a émis un document et que personne ne l'a modifié depuis."}
    source: {name: "Règlement (UE) no 910/2014, version française, article 3, cachet électronique (English: electronic seal)", url: "https://eur-lex.europa.eu/eli/reg/2014/910/2024-05-20/fra", checked: "2026-11-11"}
  - id: time-stamp
    kind: term
    en: {full: "time stamp", definition: "A token in which a trusted authority signs a hash and the time at which it saw that hash."}
    fr: {full: "horodatage électronique", definition: "Jeton dans lequel une autorité de confiance signe un condensé et l'heure à laquelle elle l'a reçu."}
    source: {name: "Règlement (UE) no 910/2014, version française, article 3, horodatage électronique (English: electronic time stamp)", url: "https://eur-lex.europa.eu/eli/reg/2014/910/2024-05-20/fra", checked: "2026-11-11"}
  - id: transparency-log
    kind: term
    en: {full: "transparency log", definition: "A public, append-only list of entries in a Merkle tree, whose signed checkpoints let anyone check that an entry is in the list and that the list only grows."}
    fr: {full: "journal de transparence", definition: "Liste publique d'entrées, en ajout seul, dans un arbre de Merkle, dont les points de contrôle signés permettent à quiconque de vérifier qu'une entrée s'y trouve et que la liste ne fait que croître."}
    source: {name: "RFC 9162 for the English form; French form to confirm (no GDT record found)", url: "https://www.rfc-editor.org/info/rfc9162", checked: "2026-11-11"}
  - id: checkpoint
    kind: term
    en: {full: "checkpoint", definition: "A short signed statement of the size and the root hash of a transparency log at one moment."}
    fr: {full: "point de contrôle", definition: "Court énoncé signé de la taille et du condensé racine d'un journal de transparence à un moment donné."}
    source: {name: "C2SP tlog-checkpoint v1.1.0; the French form follows fpsot-spec-observability (no GDT record found for this sense)", url: "https://github.com/C2SP/C2SP/blob/b2dd9892338af7009733a4575a6da05811ffae6c/tlog-checkpoint.md", checked: "2026-11-11"}
  - id: witness
    kind: term
    en: {full: "witness", definition: "An independent party that cosigns a checkpoint of a transparency log only after it checks that the log has only grown since the last checkpoint it saw."}
    fr: {full: "témoin", definition: "Partie indépendante qui ne cosigne un point de contrôle d'un journal de transparence qu'après avoir vérifié que le journal n'a fait que croître depuis le dernier point de contrôle vu."}
    source: {name: "C2SP tlog-witness v1.1.0; the French form follows fpsot-spec-observability (no GDT record found for this sense)", url: "https://github.com/C2SP/C2SP/blob/b2dd9892338af7009733a4575a6da05811ffae6c/tlog-witness.md", checked: "2026-11-11"}
  - id: inclusion-proof
    kind: term
    en: {full: "inclusion proof", definition: "The list of hashes that links one entry to the root hash of a Merkle tree, and so proves that the tree holds the entry."}
    fr: {full: "preuve d'inclusion", definition: "Liste de condensés qui relie une entrée au condensé racine d'un arbre de Merkle, et prouve ainsi que l'arbre contient l'entrée."}
    source: {name: "RFC 9162, section 2.1.3; French form to confirm (no GDT record found)", url: "https://www.rfc-editor.org/info/rfc9162", checked: "2026-11-11"}
  - id: evidence-record
    kind: term
    en: {full: "evidence record", definition: "A structure of hash trees and time stamps that proves that data existed unchanged since a given time, and that one renews before its algorithms weaken."}
    fr: {full: "dossier de preuves", definition: "Structure d'arbres de hachage et d'horodatages qui prouve que des données existent sans changement depuis un moment donné, et qu'on renouvelle avant que ses algorithmes ne faiblissent."}
    source: {name: "RFC 4998, Evidence Record Syntax; French form to confirm (no GDT record found)", url: "https://www.rfc-editor.org/info/rfc4998", checked: "2026-11-11"}
  - id: trust-anchor
    kind: term
    en: {full: "trust anchor", definition: "A public key or certificate that a verifier trusts without proof, and from which it checks the chains of other certificates."}
    fr: {full: "ancre de confiance", definition: "Clé publique ou certificat auquel un vérificateur se fie sans preuve, et à partir duquel il vérifie la chaîne des autres certificats."}
    source: {name: "RFC 5280 usage for the English form; French form to confirm (no GDT record found; TERMIUM Plus not checked)", url: "https://www.rfc-editor.org/info/rfc5280", checked: "2026-11-11"}
  - id: monitor
    kind: term
    en: {full: "monitor", definition: "A party that reads every entry of a transparency log and compares it with what the issuer meant to publish."}
    fr: {full: "vigie", definition: "Partie qui lit chaque entrée d'un journal de transparence et la compare avec ce que l'émetteur voulait publier."}
    source: {name: "RFC 9162, section 8.2 for the English form; French form to confirm (vigie is the usual Québec word for a watch function)", url: "https://www.rfc-editor.org/info/rfc9162", checked: "2026-11-11"}
  - id: mirror
    kind: term
    en: {full: "mirror", definition: "A party that keeps and serves a full copy of a transparency log, so that the log outlives its operator."}
    fr: {full: "miroir", definition: "Partie qui conserve et diffuse une copie complète d'un journal de transparence, pour que le journal survive à son exploitant."}
    source: {name: "C2SP tlog-mirror v0.1.0; Grand dictionnaire terminologique, site miroir, to confirm", url: "https://github.com/C2SP/C2SP/blob/b2dd9892338af7009733a4575a6da05811ffae6c/tlog-mirror.md", checked: "2026-11-11"}
```
