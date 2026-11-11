#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks the example files of the FPSOT signed records and transparency log
specification.

Usage: check-examples.py DIR

DIR holds four files:
  - sealed-record.txt: a stand-in for the sealed bytes of one record;
  - records-log.tlog-policy: the published witness policy of the log
    (LOG-040, LOG-041), in the C2SP tlog-policy format;
  - sealed-record.tlog-proof: the proof that goes with the record (LOG-050,
    LOG-051), in the C2SP tlog-proof@v1 format;
  - seal-manifest.json: the seal manifest of the record (LOG-017 to LOG-019).

The check uses the Python standard library only. It verifies the Ed25519 log
signature and the Ed25519 witness cosignatures with a small verifier written
from RFC 8032, evaluates the quorum of the policy, recomputes the leaf from the
salt and the sealed bytes (LOG-031), and verifies the inclusion proof against
the root of the checkpoint (RFC 6962). It also checks that the checkpoint has
no extension lines (LOG-033), that the policy asks for at least two public
witnesses and one domestic witness (LOG-041), and that the manifest has the
required fields with allowed values and holds neither the salt nor personal
information (LOG-019, LOG-085). It rejects a policy that gives the same key on two
lines, which tlog-policy forbids. For the shard year of LOG-035 it uses the year
of sealedAt, since the examples carry no logging time.

It does not check the seal itself: a seal needs an AdES validator, which the
standard library does not offer. ML-DSA-44 cosignatures are recognized but not
verified, so they do not count toward the quorum here.
"""
import base64
import hashlib
import json
import pathlib
import re
import sys

errors = []


def fail(where, message):
    errors.append(f"{where}: {message}")


# --- Ed25519 verification, from the definitions of RFC 8032 -----------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % P
    pb = (y1 + x1) * (y2 + x2) % P
    pc = 2 * t1 * t2 * D % P
    pd = 2 * z1 * z2 % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point):
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P:
            x = x * SQRT_M1 % P
        if (x * x - x2) % P:
            return None
        if (x & 1) != sign:
            x = P - x
    return (x, y, 1, x * y % P)


BASE = _decode(int.to_bytes(4 * pow(5, P - 2, P) % P, 32, "little"))


def ed25519_verify(public_key, message, signature):
    if len(signature) != 64:
        return False
    a, r = _decode(public_key), _decode(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return _encode(_mul(s, BASE)) == _encode(_add(r, _mul(h, a)))


# --- Encodings ---------------------------------------------------------------

def b64(where, text):
    """Decodes canonical standard base64, as the C2SP formats require."""
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:
        fail(where, f"not base64: {text[:40]}")
        return None
    if base64.b64encode(data).decode("ascii") != text:
        fail(where, f"base64 is not canonical: {text[:40]}")
        return None
    return data


def key_id(name, sig_type, public_key):
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public_key).digest()[:4]


def parse_vkey(where, text):
    """Parses a signed-note verifier key: name+hex(key ID)+base64(type || key)."""
    parts = text.split("+", 2)
    if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{8}", parts[1]):
        fail(where, f"not a verifier key: {text[:60]}")
        return None
    data = b64(where, parts[2])
    if not data:
        return None
    name, sig_type, public_key = parts[0], data[0], data[1:]
    if key_id(name, sig_type, public_key).hex() != parts[1]:
        fail(where, f"the key ID of {name} does not match its key")
        return None
    return {"name": name, "type": sig_type, "key": public_key, "id": bytes.fromhex(parts[1])}


# --- tlog-policy ------------------------------------------------------------

def repeated_key(here, vkey, seen_keys, n):
    """Reports a log or witness key whose type and public key an earlier line already gave."""
    k = (vkey["type"], vkey["key"])
    if k in seen_keys:
        fail(here, f"{vkey['name']} repeats the key of an earlier line ({seen_keys[k]}), which tlog-policy forbids")
        return True
    seen_keys[k] = f"line {n}"
    return False


def parse_policy(path):
    where = path.name
    policy = {"logs": [], "witnesses": {}, "groups": {}, "quorum": None}
    quorums = 0
    seen_keys = {}  # (type, public key) -> line of its first use; tlog-policy forbids repeats.
    for n, raw in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        here = f"{where}:{n}"
        if tokens[0] == "log" and len(tokens) in (2, 3):
            vkey = parse_vkey(here, tokens[1])
            if vkey and not repeated_key(here, vkey, seen_keys, n):
                if vkey["type"] != 0x01:
                    fail(here, "the log key must be an Ed25519 key, type 0x01 (OBS-112, LOG-032)")
                policy["logs"].append(vkey)
        elif tokens[0] == "witness" and len(tokens) in (3, 4):
            if tokens[1] in policy["witnesses"] or tokens[1] in policy["groups"]:
                fail(here, f"the name {tokens[1]} is defined twice")
            vkey = parse_vkey(here, tokens[2])
            if vkey and not repeated_key(here, vkey, seen_keys, n):
                if vkey["type"] not in (0x04, 0x06):
                    fail(here, "a witness key must be an Ed25519 or ML-DSA-44 cosigner key (LOG-043)")
                policy["witnesses"][tokens[1]] = vkey
        elif tokens[0] == "group" and len(tokens) >= 4:
            name, threshold, members = tokens[1], tokens[2], tokens[3:]
            for m in members:
                if m not in policy["witnesses"] and m not in policy["groups"]:
                    fail(here, f"group {name} names {m} before it is defined")
            if len(set(members)) != len(members):
                fail(here, f"group {name} lists a member twice")
            if threshold == "all":
                k = len(members)
            elif threshold == "any":
                k = 1
            elif re.fullmatch(r"[1-9][0-9]*", threshold) and int(threshold) <= len(members):
                k = int(threshold)
            else:
                fail(here, f"group {name} has a bad threshold {threshold}")
                k = len(members)
            policy["groups"][name] = (k, members)
        elif tokens[0] == "quorum" and len(tokens) == 2:
            quorums += 1
            policy["quorum"] = tokens[1]
        else:
            fail(here, f"unknown or malformed line: {line[:60]}")
    if quorums != 1:
        fail(where, f"a policy needs exactly one quorum line, found {quorums}")
    if policy["quorum"] == "none":
        fail(where, "quorum none is not allowed: a records log needs witnesses (LOG-041)")
    elif policy["quorum"] and policy["quorum"] not in policy["witnesses"] and policy["quorum"] not in policy["groups"]:
        fail(where, f"the quorum names {policy['quorum']}, which is not defined")
    if len(policy["logs"]) != 1:
        fail(where, f"the policy of one log shard names exactly one log, found {len(policy['logs'])} (LOG-040)")
    return policy


def satisfied(policy, name, signed):
    if name in policy["witnesses"]:
        return name in signed
    if name not in policy["groups"]:
        return False
    k, members = policy["groups"][name]
    return sum(satisfied(policy, m, signed) for m in members) >= k


def leaves(policy, name):
    if name in policy["witnesses"]:
        return {name}
    out = set()
    for m in policy["groups"].get(name, (0, []))[1]:
        out |= leaves(policy, m)
    return out


def check_quorum_shape(policy, where):
    """LOG-041: at least two public witnesses and at least one domestic witness."""
    quorum = policy["quorum"]
    if not quorum or quorum == "none" or quorum not in policy["witnesses"] and quorum not in policy["groups"]:
        return
    for group in ("public", "domestic"):
        if group not in policy["groups"]:
            fail(where, f"the policy has no group named {group} (LOG-041)")
            return
    public, domestic = leaves(policy, "public"), leaves(policy, "domestic")
    if public & domestic:
        fail(where, "a witness belongs to both the public and the domestic group (LOG-041)")
    if satisfied(policy, quorum, set(policy["witnesses"]) - domestic):
        fail(where, "the quorum is met without any domestic witness (LOG-041)")
    for one in public:
        if satisfied(policy, quorum, domestic | {one}):
            fail(where, "the quorum is met with fewer than two public witnesses (LOG-041)")
            break


# --- tlog-proof and checkpoint ----------------------------------------------

def parse_proof(path):
    where = path.name
    text = path.read_text(encoding="utf-8")
    head, sep, note = text.partition("\n\n")
    if not sep:
        fail(where, "no empty line between the proof and the checkpoint")
        return None
    lines = head.split("\n")
    if lines[0] != "c2sp.org/tlog-proof@v1":
        fail(where, "the first line must be c2sp.org/tlog-proof@v1 (LOG-050)")
        return None
    i, extra = 1, None
    if i < len(lines) and lines[i].startswith("extra "):
        extra = b64(where, lines[i][6:])
        i += 1
    if i >= len(lines) or not re.fullmatch(r"index (0|[1-9][0-9]*)", lines[i]):
        fail(where, "missing or malformed index line")
        return None
    index = int(lines[i][6:])
    path_hashes = []
    for h in lines[i + 1:]:
        data = b64(where, h)
        if data is not None and len(data) != 32:
            fail(where, "an inclusion proof hash is not 32 bytes")
        path_hashes.append(data or b"")
    return {"extra": extra, "index": index, "path": path_hashes, "note": note}


def parse_checkpoint(where, note):
    body, sep, sigs = note.rpartition("\n\n")
    if not sep or not note.endswith("\n"):
        fail(where, "the checkpoint is not a signed note")
        return None
    body += "\n"
    lines = body.split("\n")[:-1]
    if len(lines) < 3:
        fail(where, "the checkpoint needs an origin, a size and a root hash")
        return None
    if len(lines) > 3:
        fail(where, "the checkpoint has extension lines, which LOG-033 forbids")
    if not re.fullmatch(r"(0|[1-9][0-9]*)", lines[1]):
        fail(where, "the tree size is not a decimal number")
        return None
    root = b64(where, lines[2])
    signatures = []
    for line in sigs.rstrip("\n").split("\n"):
        m = re.fullmatch(r"— (\S+) (\S+)", line)
        if not m:
            fail(where, f"malformed signature line: {line[:60]}")
            continue
        data = b64(where, m.group(2))
        if data and len(data) > 4:
            signatures.append((m.group(1), data[:4], data[4:]))
    return {"origin": lines[0], "size": int(lines[1]), "root": root, "body": body.encode(), "signatures": signatures}


def verify_signatures(where, checkpoint, policy):
    """Verifies the log signature, then each cosignature; returns the names that cosigned."""
    log_ok = False
    for log in policy["logs"]:
        if log["name"] != checkpoint["origin"]:
            fail(where, f"the policy names the log {log['name']}, but the checkpoint origin is {checkpoint['origin']}")
            continue
        for name, kid, sig in checkpoint["signatures"]:
            if name == log["name"] and kid == log["id"]:
                if ed25519_verify(log["key"], checkpoint["body"], sig):
                    log_ok = True
                else:
                    fail(where, "the log signature does not verify")
    if not log_ok:
        fail(where, "no valid Ed25519 log signature from the key of the policy (OBS-112)")
    signed = set()
    for wname, w in policy["witnesses"].items():
        for name, kid, sig in checkpoint["signatures"]:
            if name != w["name"] or kid != w["id"]:
                continue
            if w["type"] == 0x06:
                continue  # ML-DSA-44: recognized, not verified with the standard library.
            if len(sig) != 72:
                fail(where, f"the cosignature of {wname} has the wrong length")
                continue
            ts = int.from_bytes(sig[:8], "big")
            message = f"cosignature/v1\ntime {ts}\n".encode() + checkpoint["body"]
            if ed25519_verify(w["key"], message, sig[8:]):
                signed.add(wname)
            else:
                fail(where, f"the cosignature of {wname} does not verify")
    return signed


def root_from_inclusion(index, size, leaf_hash, path):
    """Computes the root from an inclusion proof, as RFC 9162 section 2.1.3.2 describes."""
    if index >= size:
        return None
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


# --- Seal manifest ----------------------------------------------------------

UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
SIN = re.compile(r"(?<![\w.-])\d{3}[ -]?\d{3}[ -]?\d{3}(?![\w.-])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
FORMATS = {"application/json": "jades", "application/pdf": "pades", "application/xml": "xades"}
REQUIRED = ("id", "profile", "mediaType", "format", "formatVersion", "level", "signerType",
            "algorithm", "certificateSha256", "trustAnchorSet", "assuranceLevel", "sealedAt",
            "timeStampAuthority", "retentionRule")
FORBIDDEN = ("salt", "content", "body", "record", "name", "email", "subject")
PROFILES = ("seal", "seal-log", "seal-log-preserve")
LEVELS = ("b-lt", "b-lta")
SIGNERS = ("organizational-seal", "personal-signature")
ALGORITHMS = ("ecdsa-p384-sha384", "rsa-3072-sha384", "rsa-4096-sha384", "rsa-pss-3072-sha384", "rsa-pss-4096-sha384")
SCHEMES = {"tbs": ("1", "2", "3", "4"), "icpg": ("base", "moyen", "eleve"), "eidas": ("advanced", "qualified")}


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def check_manifest(path):
    where = path.name
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        fail(where, f"not JSON: {e}")
        return None
    if not isinstance(m, dict):
        fail(where, "the manifest must be a JSON object")
        return None
    for key in REQUIRED:
        if key not in m:
            fail(where, f"missing field {key} (LOG-019)")
    for key in m:
        if key.lower() in FORBIDDEN:
            fail(where, f"the manifest must not hold the field {key}: no salt, content or personal information (LOG-019)")
        if not re.fullmatch(r"[a-z][A-Za-z0-9]*", key):
            fail(where, f"field {key} is not lowerCamelCase (NAM-010)")
    if "id" in m and not UUID7.match(str(m["id"])):
        fail(where, "id must be a UUID version 7")
    if m.get("profile") not in PROFILES:
        fail(where, f"profile must be one of {', '.join(PROFILES)} (LOG-002)")
    media, fmt = m.get("mediaType"), m.get("format")
    if fmt not in ("jades", "pades", "xades", "asic-e"):
        fail(where, "format must be jades, pades, xades or asic-e (LOG-010)")
    elif FORMATS.get(media, "asic-e") != fmt:
        fail(where, f"a record of media type {media} takes the format {FORMATS.get(media, 'asic-e')}, not {fmt} (LOG-011)")
    if m.get("level") not in LEVELS:
        fail(where, "level must be b-lt or b-lta: B-B and B-T do not conform (LOG-013)")
    if m.get("signerType") not in SIGNERS:
        fail(where, f"signerType must be one of {', '.join(SIGNERS)} (LOG-014)")
    if m.get("algorithm") not in ALGORITHMS:
        fail(where, f"the seal algorithm {m.get('algorithm')} is not allowed (LOG-015)")
    if "certificateSha256" in m and not re.fullmatch(r"[0-9a-f]{64}", str(m["certificateSha256"])):
        fail(where, "certificateSha256 must be 64 lower-case hexadecimal digits")
    if not str(m.get("trustAnchorSet", "")).startswith("https://"):
        fail(where, "trustAnchorSet must be the https URL of a published trust-anchor set (LOG-017, LOG-018)")
    level = m.get("assuranceLevel")
    if not isinstance(level, dict) or level.get("scheme") not in SCHEMES \
            or level.get("value") not in SCHEMES.get(level.get("scheme"), ()):
        fail(where, "assuranceLevel needs a known scheme and value (LOG-018)")
    if "sealedAt" in m and not INSTANT.match(str(m["sealedAt"])):
        fail(where, "sealedAt must be an RFC 3339 instant in UTC")
    if not str(m.get("timeStampAuthority", "")).startswith("https://"):
        fail(where, "timeStampAuthority must be the https URL of the time-stamp authority (LOG-020)")
    if m.get("profile") in ("seal-log", "seal-log-preserve"):
        log = m.get("log")
        if not isinstance(log, dict) or not all(k in log for k in ("origin", "index", "entryHash")):
            fail(where, "a manifest of the seal-log profiles needs log.origin, log.index and log.entryHash (LOG-019)")
    if "hybridWith" in m:
        other = m["hybridWith"]
        if not isinstance(other, dict) or not str(other.get("algorithm", "")) \
                or not re.fullmatch(r"[0-9a-f]{64}", str(other.get("certificateSha256", ""))):
            fail(where, "hybridWith needs the algorithm and the certificateSha256 of the other seal of the pair (LOG-019, LOG-091)")
    for s in strings(m):
        if SIN.search(s):
            fail(where, "something that looks like a social insurance number (LOG-085)")
        if EMAIL.search(s):
            fail(where, "something that looks like an email address (LOG-085)")
    return m


# --- Main -------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print("usage: check-examples.py DIR", file=sys.stderr)
        return 2
    folder = pathlib.Path(sys.argv[1])
    files = {n: folder / n for n in ("sealed-record.txt", "records-log.tlog-policy",
                                     "sealed-record.tlog-proof", "seal-manifest.json")}
    for name, path in files.items():
        if not path.is_file():
            fail(name, "missing file")
    if errors:
        print("\n".join(errors))
        return 1

    policy = parse_policy(files["records-log.tlog-policy"])
    check_quorum_shape(policy, files["records-log.tlog-policy"].name)
    proof = parse_proof(files["sealed-record.tlog-proof"])
    manifest = check_manifest(files["seal-manifest.json"])
    where = files["sealed-record.tlog-proof"].name
    if proof:
        checkpoint = parse_checkpoint(where, proof["note"])
        if checkpoint:
            signed = verify_signatures(where, checkpoint, policy)
            if policy["quorum"] and not satisfied(policy, policy["quorum"], signed):
                fail(where, "the cosignatures do not meet the quorum of the policy (LOG-046)")
            salt = proof["extra"]
            if salt is None or len(salt) < 32:
                fail(where, "the extra line must carry the salt of 32 bytes or more (LOG-051, OBS-111)")
            else:
                sealed = files["sealed-record.txt"].read_bytes()
                entry = hashlib.sha256(salt + sealed).digest()
                leaf = hashlib.sha256(b"\x00" + entry).digest()
                root = root_from_inclusion(proof["index"], checkpoint["size"], leaf, proof["path"])
                if root is None or root != checkpoint["root"]:
                    fail(where, "the inclusion proof does not lead from the leaf to the root of the checkpoint (LOG-051)")
                if manifest and isinstance(manifest.get("log"), dict):
                    log = manifest["log"]
                    mwhere = files["seal-manifest.json"].name
                    if log.get("origin") != checkpoint["origin"]:
                        fail(mwhere, "log.origin differs from the origin of the checkpoint")
                    if log.get("index") != proof["index"]:
                        fail(mwhere, "log.index differs from the index of the proof")
                    if log.get("entryHash") != base64.b64encode(entry).decode():
                        fail(mwhere, "log.entryHash is not the salted hash of the sealed bytes (LOG-031)")
            # LOG-035: an entry belongs to the shard of the UTC year in which the log takes it.
            # The example files carry no logging time, so sealedAt stands in for it. A record
            # sealed just before the end of a year and logged after it would fail here wrongly.
            year = str(manifest.get("sealedAt", ""))[:4] if manifest else ""
            if year and not checkpoint["origin"].endswith("-" + year):
                fail(where, f"the origin {checkpoint['origin']} does not name the shard of the year {year}, taken from sealedAt (LOG-035)")

    if errors:
        print("\n".join(errors))
        return 1
    print("OK: policy, proof, checkpoint signatures, quorum, inclusion and manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
