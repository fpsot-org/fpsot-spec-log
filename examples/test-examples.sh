#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the example check of examples/check-examples.py:
#   - the examples in this folder pass the check;
#   - each broken copy below fails it, with the expected message. A check that
#     accepts a broken file would hide every later error.
#
# Needs only Python 3 and its standard library. Environment: PYTHON (default
# python3).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
python=${PYTHON:-python3}
fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
files=(sealed-record.txt records-log.tlog-policy sealed-record.tlog-proof seal-manifest.json)

check() { $python -I "$here/check-examples.py" "$1"; }

if ! out=$(check "$here"); then
  echo "FAIL: the examples do not pass the check:"; echo "$out"; fail=1
fi

# broken NAME FILE PYTHON-EXPRESSION EXPECTED-TEXT
# Copies the examples, rewrites FILE with the expression (applied to its text
# as the variable t), and expects the check to fail with EXPECTED-TEXT.
broken() {
  local name=$1 file=$2 expr=$3 want=$4 dir="$work/$1"
  mkdir -p "$dir"
  for f in "${files[@]}"; do cp "$here/$f" "$dir/"; done
  $python -I -c "import sys,pathlib; p=pathlib.Path(sys.argv[1]); t=p.read_text(encoding='utf-8'); p.write_text($expr, encoding='utf-8')" "$dir/$file"
  if out=$(check "$dir"); then
    echo "FAIL: the check accepted the broken copy $name"; fail=1; return
  fi
  if ! grep -qF -- "$want" <<<"$out"; then
    echo "FAIL: the check rejected $name, but not for the expected reason: $want"; echo "$out"; fail=1
  fi
}

# The record changed after it was logged: the leaf no longer matches.
broken changed-record sealed-record.txt "t.replace('2027-0042', '2027-0043')" "inclusion proof does not lead"
# A wrong salt in the extra line.
broken wrong-salt sealed-record.tlog-proof "t.replace('extra zWqe', 'extra zWqf', 1)" "inclusion proof does not lead"
# A changed root hash breaks the log signature and every cosignature.
broken changed-root sealed-record.tlog-proof "t.replace('Rl/dUEiI1', 'Rl/dUEiI2', 1)" "log signature does not verify"
# An extension line in the checkpoint (LOG-033).
broken extension-line sealed-record.tlog-proof "t.replace('YFOAvi4=\n\n', 'YFOAvi4=\nnote: extra claim\n\n', 1)" "extension lines"
# A cosignature removed: the quorum is no longer met (LOG-046).
broken missing-cosignature sealed-record.tlog-proof "'\n'.join(l for l in t.split('\n') if 'archives.example/witness' not in l)" "do not meet the quorum"
# A forged cosignature.
broken forged-cosignature sealed-record.tlog-proof "t.replace('hxgnFgAAAABrl/lsP+IJ', 'hxgnFgAAAABrl/lsP+IK', 1)" "cosignature of alpha does not verify"
# Base64 that is not canonical.
broken non-canonical sealed-record.tlog-proof "t.replace('extra zWqefgN0s95vOQ0sDPG6pY78usFJhOtjqDvs3sQGHQo=', 'extra zWqefgN0s95vOQ0sDPG6pY78usFJhOtjqDvs3sQGHQp=', 1)" "not canonical"
# No witnesses at all (LOG-041).
broken quorum-none records-log.tlog-policy "t.replace('quorum public-and-domestic', 'quorum none')" "quorum none is not allowed"
# A quorum that the public witnesses alone can meet (LOG-041).
broken no-domestic records-log.tlog-policy "t.replace('quorum public-and-domestic', 'quorum public')" "without any domestic witness"
# A quorum of one public witness and one domestic witness (LOG-041).
broken one-public records-log.tlog-policy "t.replace('group public 2 alpha', 'group public 1 alpha')" "fewer than two public witnesses"
# One witness listed twice under two names: the quorum would count one key twice.
broken duplicate-witness-key records-log.tlog-policy "t.replace('witness beta witness.example.com/beta+e966ab90+BD9nnkxq35cI2jHwW0OsWK7Oc0dVqpNMrmQE7srZyqEQ', 'witness beta witness.example.net/alpha+87182716+BF2ykSyHeHJwnvOG+h1Vj7aGmwHJaXQRLPRrIQ3n1vce')" "repeats the key of an earlier line"
# The policy names another log.
broken other-log records-log.tlog-policy "t.replace('log records.example.org/notices-2027+', 'log records.example.org/notices-2026+')" "key ID of records.example.org/notices-2026 does not match"
# A level below B-LT (LOG-013).
broken level-b-t seal-manifest.json "t.replace('\"b-lt\"', '\"b-t\"')" "B-B and B-T do not conform"
# A seal made with the log key algorithm (LOG-015).
broken ed25519-seal seal-manifest.json "t.replace('ecdsa-p384-sha384', 'ed25519')" "seal algorithm ed25519 is not allowed"
# A JSON record sealed as PAdES (LOG-011).
broken wrong-format seal-manifest.json "t.replace('\"jades\"', '\"pades\"')" "takes the format jades"
# The salt copied into the manifest (LOG-019).
broken salt-in-manifest seal-manifest.json "t.replace('\"profile\"', '\"salt\": \"zWqefgN0s95vOQ0sDPG6pY78usFJhOtjqDvs3sQGHQo=\", \"profile\"', 1)" "must not hold the field salt"
# Personal information in the manifest (LOG-085).
broken email-in-manifest seal-manifest.json "t.replace('example-schedule/rule-1-4-2', 'firstname.lastname@example.org')" "email address"
# A manifest whose entry hash does not match the record (LOG-031).
broken wrong-entry seal-manifest.json "t.replace('UOrD3F5XL', 'UOrD3F5XM')" "log.entryHash is not the salted hash"
# A hybrid pair that does not identify the other seal (LOG-019, LOG-091).
broken bad-hybrid seal-manifest.json "t.replace('\"profile\"', '\"hybridWith\": {\"algorithm\": \"ml-dsa-87\"}, \"profile\"', 1)" "hybridWith needs"
# A record of 2027 in the shard of 2026 (LOG-035).
broken wrong-year seal-manifest.json "t.replace('2027-03-15T14:30:00Z', '2026-12-31T23:30:00Z')" "does not name the shard of the year 2026"

[ $fail -eq 0 ] && echo "PASS"
exit $fail
