#!/usr/bin/env python3
"""Independent checker for the draft-hulea-wimse-agent-mandate-00 vectors.

It shares no code with generate.py. For each case it reads only the published
files (keys via trust-anchors.json, the profile bytes, the presentation and the
inputs), verifies every signature, runs the Section 9.3 procedure as far as these
cases exercise it, builds a Validation Result, and compares it with
expected-result.json as a JSON value under the identity rules of Section 4.6.

Usage: python check.py [vectors_dir]
"""

import base64
import hashlib
import json
import os
import sys
from decimal import Decimal

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROLE_NAMES = ["mandate_issuer", "authority_source", "operator", "verifier",
              "exposure_observer", "status_issuer"]
STATEFUL = {"sum_max", "cosign_above"}
LIST_MEMBERS = ("locations", "actions", "datatypes", "privileges")


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def dig(data: bytes):
    return b64u(hashlib.sha256(data).digest())


def jwk_thumbprint(jwk):
    m = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                   separators=(",", ":")).encode("utf-8")
    return dig(m)


# ---------------------------------------------------------------- Section 4.6

def identical(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        # Identical only if textual representations are identical.
        return (isinstance(a, (int, float)) and isinstance(b, (int, float))
                and type(a) is type(b) and repr(a) == repr(b))
    if isinstance(a, list) or isinstance(b, list):
        return (isinstance(a, list) and isinstance(b, list) and len(a) == len(b)
                and all(identical(x, y) for x, y in zip(a, b)))
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(identical(a[k], b[k]) for k in a)
    return False


def diff_paths(a, b, path="$"):
    if identical(a, b):
        return []
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}.{k}: present only in {'expected' if k in b else 'computed'}")
            else:
                out += diff_paths(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff_paths(x, y, f"{path}[{i}]")
        return out
    return [f"{path}: computed {json.dumps(a)} expected {json.dumps(b)}"]


# ---------------------------------------------------------------- JWS

class Artifact:
    def __init__(self, compact):
        self.compact = compact
        self.ref = {"dig": dig(compact.encode("ascii"))}
        self.ok = True
        try:
            h, p, s = compact.split(".")
            self.header = json.loads(b64u_dec(h))
            self.payload = json.loads(b64u_dec(p))
            self.sig = b64u_dec(s)
            self.signing_input = (h + "." + p).encode("ascii")
        except Exception:
            self.ok = False
            self.header, self.payload = {}, {}

    @property
    def typ(self):
        return self.header.get("typ")

    def verify(self, jwk):
        if self.header.get("alg") != "EdDSA" or jwk.get("crv") != "Ed25519":
            return False
        try:
            Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"])).verify(self.sig, self.signing_input)
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------- Permissions

def resolve(ptr, doc):
    if ptr == "":
        return True, doc
    if not ptr.startswith("/"):
        return False, None
    cur = doc
    for tok in ptr[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and tok in cur:
            cur = cur[tok]
        elif isinstance(cur, list) and tok.isdigit() and (tok == "0" or not tok.startswith("0")) and int(tok) < len(cur):
            cur = cur[int(tok)]
        else:
            return False, None
    return True, cur


def first_token(ptr):
    return ptr[1:].split("/")[0].replace("~1", "/").replace("~0", "~")


def is_decimal(v):
    import re
    return isinstance(v, str) and re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", v) is not None


def is_nonneg(v):
    return is_decimal(v) and not v.startswith("-")


def constrained_members(perm):
    return {first_token(c["ptr"]) for c in perm.get("constraints", []) if "ptr" in c}


def admitted(member, perm, type_profile):
    return (member == "type" or member in LIST_MEMBERS or member in perm
            or member in constrained_members(perm)
            or member in type_profile.get("admitted", []))


def constraint_satisfied(c, req, T, predicates):
    pred = c["pred"]
    if pred not in predicates:
        return False
    if pred == "window":
        return c["value"]["nbf"] <= T < c["value"]["exp"]
    found, v = resolve(c["ptr"], req)
    if not found:
        return False
    if pred == "eq":
        return identical(v, c["value"])
    if pred == "in":
        return any(identical(v, e) for e in c["value"])
    if pred == "max":
        return is_decimal(v) and Decimal(v) <= Decimal(c["value"])
    if pred == "min":
        return is_decimal(v) and Decimal(v) >= Decimal(c["value"])
    if pred == "sum_max":
        return is_nonneg(v)
    if pred == "cosign_above":
        return is_decimal(v)
    return False


def matches(req, perm, T, profile):
    types = profile["types"]
    if req.get("type") != perm.get("type") or perm.get("type") not in types:
        return False
    tp = types[perm["type"]]
    for m in LIST_MEMBERS:
        if m in perm:
            if m not in req or not isinstance(req[m], list):
                return False
            if not all(any(identical(r, p) for p in perm[m]) for r in req[m]):
                return False
    for m, v in perm.items():
        if m in LIST_MEMBERS or m in ("constraints", "type"):
            continue
        if m not in req or not identical(req[m], v):
            return False
    for m in req:
        if not admitted(m, perm, tp):
            return False
    for c in perm.get("constraints", []):
        if not constraint_satisfied(c, req, T, profile["predicates"]):
            return False
    return True


def at_least_as_strict(cc, pc):
    p = pc["pred"]
    if p == "eq":
        return cc["pred"] == "eq" and identical(cc["value"], pc["value"])
    if p == "in":
        if cc["pred"] == "in":
            return all(any(identical(x, y) for y in pc["value"]) for x in cc["value"])
        return cc["pred"] == "eq" and any(identical(cc["value"], y) for y in pc["value"])
    if p == "max":
        return cc["pred"] == "max" and Decimal(cc["value"]) <= Decimal(pc["value"])
    if p == "min":
        return cc["pred"] == "min" and Decimal(cc["value"]) >= Decimal(pc["value"])
    if p == "window":
        return (cc["pred"] == "window" and cc["value"]["nbf"] >= pc["value"]["nbf"]
                and cc["value"]["exp"] <= pc["value"]["exp"])
    if p == "sum_max":
        return (cc["pred"] == "sum_max" and cc["budget"] == pc["budget"]
                and Decimal(cc["value"]) <= Decimal(pc["value"]) and cc["period"] >= pc["period"])
    if p == "cosign_above":
        return cc["pred"] == "cosign_above" and Decimal(cc["value"]) <= Decimal(pc["value"])
    return False


def attenuated(c, p, profile):
    if c.get("type") != p.get("type"):
        return False
    tp = profile["types"].get(p["type"], {})
    for m in LIST_MEMBERS:
        if m in p:
            if m not in c or not all(any(identical(x, y) for y in p[m]) for x in c[m]):
                return False
    for m, v in p.items():
        if m in LIST_MEMBERS or m in ("constraints", "type"):
            continue
        if m not in c or not identical(c[m], v):
            return False
    for m in c:
        if m in ("type", "constraints"):
            continue
        if not admitted(m, p, tp):
            return False
    for m in constrained_members(c):
        if not admitted(m, p, tp):
            return False
    for pc in p.get("constraints", []):
        same = [cc for cc in c.get("constraints", []) if cc.get("ptr") == pc.get("ptr")]
        if not any(at_least_as_strict(cc, pc) for cc in same):
            return False
    return True


def set_attenuated(children, parents, profile):
    return all(any(attenuated(c, p, profile) for p in parents) for c in children)


# ---------------------------------------------------------------- procedure

MANDATE_REQ = ["iss", "sub", "jti", "iat", "nbf", "exp", "cnf", "principal", "delegator", "perms", "tf"]
AA_REQ = ["iss", "jti", "iat", "exp", "principal", "delegator", "powers", "tf"]
WIT_REQ = ["iss", "sub", "exp", "cnf"]


def party_ok(p):
    return isinstance(p, dict) and isinstance(p.get("id"), str) and isinstance(p.get("scheme"), str)


def sum_max_budgets_ok(perms):
    for perm in perms:
        seen = {}
        for c in perm.get("constraints", []):
            if c.get("pred") == "sum_max":
                if seen.setdefault(c.get("budget"), c.get("ptr")) != c.get("ptr"):
                    return False
    return True


def validate(vdir, cdir):
    profile_bytes = open(os.path.join(vdir, "profile", "profil.json"), "rb").read()
    profile = json.loads(profile_bytes)
    anchors = json.load(open(os.path.join(vdir, "trust-anchors.json")))
    pres = json.load(open(os.path.join(cdir, "presentation.json")))
    inputs = json.load(open(os.path.join(cdir, "inputs.json")))
    ad_bytes = open(os.path.join(cdir, "authorization_details.json"), "rb").read()
    notes = []

    if dig(profile_bytes) != inputs["profile"]["dig"]:
        raise SystemExit("profile digest does not match inputs")
    for t in profile["types"].values():
        if t["schema"].get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SystemExit("profile refused: schema without $schema 2020-12")
    if ad_bytes.decode("utf-8") != pres["authorization_details"]:
        raise SystemExit("authorization_details bytes differ from presentation")

    T = inputs["time"]
    skew = profile["max_clock_skew"]
    errors = []

    def err(code, art=None, perm=None):
        e = {"code": code}
        if art is not None:
            e["artifact"] = dict(art.ref)
        if perm is not None:
            e["perm"] = perm
        errors.append(e)

    leaf = Artifact(pres["subject_token"])
    wit = Artifact(pres["actor_token"])
    ev = [Artifact(s) for s in pres.get("mandate_evidence", [])]
    ev_mandates = {a.ref["dig"]: a for a in ev if a.typ == "mandate+jwt"}
    ev_aas = {a.ref["dig"]: a for a in ev if a.typ in ("authority+jwt", "authority+sd-jwt")}

    # Step 1: chain and context
    chain = [leaf]
    root = None
    while True:
        cur = chain[-1]
        if "parent" not in cur.payload:
            root = cur
            break
        nxt = ev_mandates.get(cur.payload["parent"].get("dig"))
        if nxt is None:
            err("chain_broken", cur)
            break
        chain.append(nxt)
    chain.reverse()  # root first
    if len(chain) > profile["max_chain_length"]:
        err("chain_too_long")
    ctx = root.payload.get("tf") if root else None
    fw = None
    if root is not None:
        fw = profile["frameworks"].get(ctx)
        if fw is None:
            err("framework_not_accepted", root)

    # Authority Assertions referenced by the root and presented
    refs = root.payload.get("authority", []) if root else []
    presented = [ev_aas[r["dig"]] for r in refs if r.get("dig") in ev_aas]
    notes.append(f"root references {len(refs)} Authority Assertion(s), {len(presented)} presented")

    # Step 2: structure
    aa_failed = {}  # dig -> True if failed any of steps 2..6

    def fail_aa(a):
        aa_failed[a.ref["dig"]] = True

    for m in chain:
        p = m.payload
        bad = (not m.ok or m.typ != "mandate+jwt" or any(k not in p for k in MANDATE_REQ)
               or not isinstance(p.get("cnf"), dict) or "jkt" not in p["cnf"]
               or not party_ok(p.get("principal")) or not party_ok(p.get("delegator"))
               or not isinstance(p.get("perms"), list) or not p["perms"]
               or not sum_max_budgets_ok(p.get("perms", [])))
        if m is root:
            if "parent" in p:
                bad = True
            if p.get("delegator") != p.get("principal") and "authority" not in p:
                bad = True
        elif "authority" in p:
            bad = True
        if bad:
            err("malformed", m)
    for a in presented:
        p = a.payload
        bad = (not a.ok or a.typ != "authority+jwt" or any(k not in p for k in AA_REQ)
               or not party_ok(p.get("principal")) or not party_ok(p.get("delegator"))
               or not isinstance(p.get("powers"), list) or not p["powers"]
               or any(c.get("pred") in STATEFUL for pw in p["powers"] for c in pw.get("constraints", [])))
        if bad:
            err("malformed", a)
            fail_aa(a)
    wp = wit.payload
    if (not wit.ok or wit.typ != "wit+jwt" or any(k not in wp for k in WIT_REQ)
            or not isinstance(wp.get("cnf"), dict) or "jwk" not in wp["cnf"]):
        err("malformed", wit)

    # Step 3: profile conformance
    # max_lifetime member names as chosen by the published profile (see README).
    lifetime_names = {
        "authority+jwt": "authority", "authority+sd-jwt": "authority",
        "mandate+jwt": "mandate", "wit+jwt": "wit",
        "eat+jwt": "attestation_result", "agent-exposure+jwt": "exposure_statement",
    }

    def lifetime_key(a):
        return lifetime_names.get(a.typ)

    if fw is not None:
        for a in chain + presented + [wit]:
            is_aa = a in presented
            afw = profile["frameworks"].get(a.payload.get("tf")) if is_aa else fw
            if afw is None:
                continue
            if a.header.get("alg") not in afw["algs"]:
                err("alg_not_allowed", a)
                if is_aa:
                    fail_aa(a)
            for party in ("principal", "delegator"):
                if party in a.payload and a.payload[party].get("scheme") not in afw["party_schemes"]:
                    err("scheme_not_accepted", a)
                    if is_aa:
                        fail_aa(a)
            lim = afw["max_lifetime"].get(lifetime_key(a))
            if "iat" in a.payload and lim is not None and a.payload["exp"] - a.payload["iat"] > lim:
                err("lifetime_exceeded", a)
                if is_aa:
                    fail_aa(a)
            if a.typ in afw["status_required"] and "status" not in a.payload:
                err("status_missing", a)
                if is_aa:
                    fail_aa(a)
        for m in chain:
            for perm in m.payload.get("perms", []):
                for c in perm.get("constraints", []):
                    if c.get("pred") == "sum_max" and c.get("period", 0) > fw["max_lifetime"]["max_period"]:
                        err("lifetime_exceeded", m)

    # Step 4: signatures and keys
    def anchors_for(role, tf):
        return [a for a in anchors[role] if tf in a["frameworks"]]

    def verify_role(art, role, tf):
        for anc in anchors_for(role, tf):
            for k in anc["keys"]:
                if art.verify(k):
                    return True
        for other in ROLE_NAMES:
            if other == role:
                continue
            for anc in anchors[other]:
                for k in anc["keys"]:
                    if art.verify(k):
                        err("role_mismatch", art)
                        return False
        err("signature_invalid", art)
        return False

    verified = set()
    if root is not None and fw is not None:
        if verify_role(root, "mandate_issuer", ctx):
            verified.add(root.ref["dig"])
    for i, m in enumerate(chain):
        if m is root:
            continue
        parent = chain[i - 1] if i > 0 else None
        jwk = m.header.get("jwk")
        if jwk is None:
            err("key_missing", m)
            continue
        if parent is None or jwk_thumbprint(jwk) != parent.payload["cnf"]["jkt"]:
            err("key_mismatch", m)
            continue
        if m.verify(jwk):
            verified.add(m.ref["dig"])
        else:
            err("signature_invalid", m)
    for a in presented:
        if verify_role(a, "authority_source", a.payload.get("tf")):
            verified.add(a.ref["dig"])
        else:
            fail_aa(a)
    if fw is not None and verify_role(wit, "operator", ctx):
        verified.add(wit.ref["dig"])

    # Step 5: framework compatibility
    if fw is not None:
        for m in chain:
            if m.payload.get("tf") != ctx:
                err("framework_mismatch", m)
        for a in presented:
            if a.payload.get("tf") not in fw["authority_frameworks"]:
                err("framework_mismatch", a)
                fail_aa(a)

    # Step 6: time
    for a in chain + presented + [wit]:
        p = a.payload
        if "nbf" in p and not p["nbf"] <= T + skew:
            err("not_yet_valid", a)
            if a in presented:
                fail_aa(a)
        if "exp" in p and not T < p["exp"] + skew:
            err("expired", a)
            if a in presented:
                fail_aa(a)

    # Step 7: status (no Status List Tokens are input in these cases)
    status_codes = {}
    for a in chain + presented + [wit]:
        if "status" in a.payload:
            err("status_unavailable", a)
            status_codes[a.ref["dig"]] = ["status_unavailable"]

    # Step 8: links (Section 4.8)
    for i in range(1, len(chain)):
        c, p = chain[i].payload, chain[i - 1].payload
        if c.get("max_depth", 0) > p.get("max_depth", 0) - 1:
            err("depth_exceeded", chain[i])
        ok = (c.get("iss") == p.get("sub") and identical(c.get("principal"), p.get("principal"))
              and c.get("tf") == p.get("tf") and c.get("exp", 0) <= p.get("exp", 0)
              and ("aud" not in p or ("aud" in c and all(x in p["aud"] for x in c["aud"])))
              and set_attenuated(c.get("perms", []), p.get("perms", []), profile))
        if not ok:
            err("not_attenuated", chain[i])

    # Step 9: authority (Section 9.4)
    if root is None:
        authority = "not_evaluated"
    elif identical(root.payload.get("delegator"), root.payload.get("principal")):
        authority = "self"
    else:
        rp_ = root.payload
        supporting, parties_match = [], False
        for a in presented:
            ap = a.payload
            pm = identical(ap.get("principal"), rp_["principal"]) and identical(ap.get("delegator"), rp_["delegator"])
            parties_match = parties_match or pm
            att = set_attenuated(rp_["perms"], ap.get("powers", []), profile)
            depth_ok = rp_.get("max_depth", 0) <= ap.get("max_depth", 0)
            passed_2_6 = not aa_failed.get(a.ref["dig"])
            notes.append(f"Authority Assertion {a.ref['dig'][:10]}: steps 2-6 {'passed' if passed_2_6 else 'failed'}, "
                         f"parties {'match' if pm else 'differ'}, root perms {'attenuated' if att else 'not attenuated'}, "
                         f"max_depth {'ok' if depth_ok else 'exceeded'}")
            if passed_2_6 and pm and att and depth_ok:
                supporting.append(a)
        if any(a.ref["dig"] not in status_codes for a in supporting):
            authority = "established"
        elif any(status_codes.get(a.ref["dig"]) == ["status_unavailable"] for a in supporting):
            authority = "unknown"
        else:
            authority = "refuted"
            if not presented:
                err("authority_missing", root)
            elif not parties_match:
                err("authority_mismatch", root)
            else:
                err("authority_insufficient", root)
        established_aas = supporting

    # Step 10: binding
    lp = leaf.payload
    wjwk = wp.get("cnf", {}).get("jwk")
    if wp.get("sub") != lp.get("sub") or wjwk is None or jwk_thumbprint(wjwk) != lp.get("cnf", {}).get("jkt"):
        err("binding_mismatch", wit)
    if inputs["pop"]["outcome"] != "ok":
        err("pop_failed")

    # Step 11: audience
    for m in chain:
        if "aud" in m.payload and inputs["rp"] not in m.payload["aud"]:
            err("audience_mismatch", m)

    # Step 12: action match
    diagnostics = []
    alternatives = []
    req_list = json.loads(ad_bytes)
    if not isinstance(req_list, list) or len(req_list) != 1:
        err("request_malformed")
    else:
        req = req_list[0]
        tp = profile["types"].get(req.get("type"))
        if tp is None:
            err("request_malformed")
        else:
            try:
                jsonschema.Draft202012Validator(tp["schema"]).validate(req)
            except jsonschema.ValidationError:
                err("request_malformed")
                req = None
        if req is not None and tp is not None:
            for idx, perm in enumerate(lp.get("perms", [])):
                if matches(req, perm, T, profile):
                    obls = []
                    for ci, c in enumerate(perm.get("constraints", [])):
                        if c["pred"] == "sum_max":
                            _, amt = resolve(c["ptr"], req)
                            obls.append({"type": "sum_max", "constraint": ci, "root": root.payload["jti"],
                                         "budget": c["budget"], "period": c["period"],
                                         "value": c["value"], "amount": amt})
                        elif c["pred"] == "cosign_above":
                            _, amt = resolve(c["ptr"], req)
                            if Decimal(amt) > Decimal(c["value"]):
                                obls.append({"type": "cosign_above", "constraint": ci,
                                             "value": c["value"], "amount": amt})
                    alternatives.append({"perm": idx, "obligations": obls})
                else:
                    diagnostics.append({"code": "perm_not_matching", "perm": idx})
            if not alternatives:
                err("action_not_permitted")

    # Result assembly
    def key(e):
        return (e["code"], e.get("artifact", {}).get("dig", ""), e.get("perm", -1))

    def dedupe_sort(lst):
        out = []
        for e in sorted(lst, key=key):
            if not out or not identical(out[-1], e):
                out.append(e)
        return out

    errors = dedupe_sort(errors)
    error_codes = {e["code"] for e in errors}
    if error_codes - {"status_unavailable"}:
        outcome = "invalid"
    elif "status_unavailable" in error_codes:
        outcome = "indeterminate"
    else:
        outcome = "valid"

    claims = []

    def add_claims(art, names, role):
        if art.ref["dig"] not in verified:
            return
        for n in names:
            if n in art.payload:
                claims.append({"claim": n, "value": art.payload[n], "artifact": dict(art.ref), "role": role})

    for m in chain:
        add_claims(m, ["iss", "sub", "principal", "delegator", "perms", "loa"],
                   "mandate_issuer" if m is root else "agent_instance")
    if root is not None and authority not in ("self", "not_evaluated"):
        sup = {a.ref["dig"] for a in established_aas}
        for r in refs:
            if r["dig"] in sup:
                a = ev_aas[r["dig"]]
                add_claims(a, ["iss", "principal", "delegator", "powers", "max_depth", "loa"], "authority_source")
    add_claims(wit, ["iss", "sub"], "operator")

    result = {
        "outcome": outcome,
        "profile": {"uri": inputs["profile"]["uri"], "dig": dig(profile_bytes)},
        "time": T,
        "tf": ctx,
        "chain": [dict(m.ref) for m in chain],
        "errors": errors,
        "diagnostics": dedupe_sort(diagnostics),
        "authority": authority,
        "claims": claims,
        "alternatives": sorted(alternatives, key=lambda x: x["perm"]),
        "evidence": [],
        "rejected": [],
        "status_evidence": [],
    }
    return result, notes


def main(vdir):
    cases_dir = os.path.join(vdir, "cases")
    all_ok = True
    for name in sorted(os.listdir(cases_dir)):
        cdir = os.path.join(cases_dir, name)
        expected = json.load(open(os.path.join(cdir, "expected-result.json")))
        computed, notes = validate(vdir, cdir)
        ok = identical(computed, expected)
        all_ok &= ok
        codes = ", ".join(e["code"] for e in computed["errors"]) or "none"
        print(f"{'PASS' if ok else 'FAIL'} {name}: outcome={computed['outcome']} "
              f"authority={computed['authority']} errors=[{codes}]")
        for n in notes:
            print(f"     {n}")
        if not ok:
            for d in diff_paths(computed, expected):
                print("     " + d)
    print("all cases agree with expected results" if all_ok else "MISMATCH")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))))
