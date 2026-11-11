"""Writes oracle.json: the known-answer vectors of KBOX-54, computed by devbox's own form functions (admin-match `cores` and `forms`, the
normative source of docs/planning/admin-secrets-spec.md section 3) on SYNTHETIC values. No store is opened and no real value is read.
Run: python3 -I generate-oracle.py <output path>. Values are hex in the output so no secret-shaped text sits in the repo."""
import base64
import importlib.machinery
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
SRC = "/home/petter/code/devbox/adminkeys/admin-match"
loader = importlib.machinery.SourceFileLoader("admin_match_oracle", SRC)
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("admin_match_oracle", loader))
loader.exec_module(mod)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


jwt = ".".join([b64u(b'{"alg":"HS256","typ":"JWT"}'), b64u(b'{"sub":"synthetic","n":1}'), b64u(bytes(range(7, 39)))])
lookalike = ".".join([b64u(b'{"typ":"JWT"}'), b64u(b'{"sub":"x"}'), b64u(bytes(range(40, 72)))])

CASES = [
    ("three bytes", "Man", None),
    ("two bytes", "ab", None),
    ("base64 specials", "k9Zq-W_x.7~Tn+/=B", None),
    ("quote backslash tab newline space", 'q"u\\o\te\nx y', None),
    ("non-ascii with astral", "kéy-€\U0001f600ñ", None),
    ("percent edge characters", "a/b?c&d=e f!*'()", None),
    ("control and delete", "ctl\x01\x1f\x7fend", None),
    ("two non-ascii chars three bytes", "éa", None),
    ("sb_secret prefix", "sb_secret_Zk3Lm9QwXv", None),
    ("GOCSPX prefix", "GOCSPX-abcDEF123ghi", None),
    ("declared prefix", "tok_9f8e7d6c5b4a", "tok_"),
    ("url with encoded password", "postgres://svc:p%40ss%2Fw0rd%21@db.example.net:5432/app?x=1", None),
    ("url with plain password", "https://svc:Hunter2Hunter2@host.example/path", None),
    ("url without password", "https://user@host.example/path", None),
    ("jwt", jwt, None),
    ("jwt lookalike without alg", lookalike, None),
]

out = []
for label, value, prefix in CASES:
    cs = mod.cores(value, prefix)
    forms = []
    for kind, core in cs:
        for name, b in mod.forms(core):
            forms.append({"core": "decoded" if kind == "dec-" else "written", "name": name, "hex": b.hex()})
    out.append({
        "label": label,
        "valueHex": value.encode().hex(),
        "prefix": prefix,
        "cores": [{"core": "decoded" if k == "dec-" else "written", "hex": c.encode().hex()} for k, c in cs],
        "forms": forms,
    })

with open(sys.argv[1], "w") as f:
    json.dump({"source": "devbox adminkeys/admin-match cores() and forms(), synthetic values", "cases": out}, f, indent=1)
    f.write("\n")
