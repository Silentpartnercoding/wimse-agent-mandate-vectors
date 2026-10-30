# Test vectors for draft-hulea-wimse-agent-mandate

Signed test vectors and an independent checker for the Internet-Draft
[draft-hulea-wimse-agent-mandate](https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/)
(revision [-00](https://datatracker.ietf.org/doc/html/draft-hulea-wimse-agent-mandate-00)),
discussed on the IETF WIMSE working group list.

The set covers the Appendix A story as a valid baseline, plus three negative
cases about the Authority Assertion. Each negative case makes one change from
the baseline.

| Case | What it tests | Change from baseline | Expected outcome | authority | errors |
|---|---|---|---|---|---|
| 00-baseline | the Appendix A presentation validates end to end | none | valid | established | none |
| 01-root-broader-than-powers | a root mandate that grants more than the Authority Assertion powers allow | root `max` on `/instructedAmount/amount` is 200000.00 (assertion powers allow 100000.00) | invalid | refuted | authority_insufficient |
| 02-authority-not-presented | a root mandate that references an Authority Assertion the presentation leaves out | the Authority Assertion is left out of `mandate_evidence`; the root still references it | invalid | refuted | authority_missing |
| 03-authority-expired | an Authority Assertion that expired before validation time | Authority Assertion `exp` is 1792886400, before T minus `max_clock_skew` | invalid | refuted | authority_insufficient, expired |

In cases 01 and 03 the change to the Authority Assertion or root changes its
digest, so the downstream Artifact References and signatures change too. In
case 02 every presented artifact is byte-identical to the baseline.

## Status

Cases 00 to 03 follow revision -00. Case 04 waits for revision -01 of the
draft and will be added here once -01 is published.

## Layout

```
keys/chei.json        the published test keys: one Ed25519 private JWK per role, with kid and RFC 7638 jkt
profile/profil.json   the published Validation Profile, exact bytes that are digested
profile/profil.digest the published digest of profil.json
profile/profile-ref.json  {uri, dig}
trust-anchors.json    the Trust Anchor Set the Validator is configured with
cases/<case>/
  *.jws                       compact JWS of each artifact
  authorization_details.json  exact request bytes
  presentation.json           subject_token, actor_token, mandate_evidence, authorization_details
  inputs.json                 time T for the case, RP identifier, profile reference, PoP outcome
  decoded.json                headers and payloads, for reading only
  expected-result.json        the Validation Result (Section 9.6)
generate.py           regenerates every case file from keys/chei.json and profile/profil.json
check.py              independent checker
tests/                runs check.py, confirms byte-identical regeneration, and checks that a
                      damaged root mandate gives an invalid result instead of an error
```

## Keys

The keys and the Validation Profile are the ones the draft author published
for Appendix B on 27 October 2026 (`chei.json`, `profil.json` and a README).
They are stored here byte for byte. `generate.py` reads them, checks every
key's `kid`, its public part against `d`, and its RFC 7638 thumbprint, and
checks the profile bytes against the published digest before it signs.

| kid | role | signs | jkt |
|---|---|---|---|
| as-1 | authority_source (https://register.example) | Authority Assertion | `__imVWcQLM0Eu_zeFJP4gPy-cT2GHpxsDIc3Q6BB9P0` |
| mi-1 | mandate_issuer (https://mandates.treasury.example) | root mandate | `m1L1fJ7hE4J3T5ICutV1puXJmaTOumHGmilPJ0Eq1eg` |
| op-1 | operator (https://treasury.example) | WIT | `T3rk4eVrInQUEZKVFF5lnJEVRXMFAEDP9EW9GZmLZPY` |
| ai-treasury-1 | agent instance payments-7 | sub-mandate, bound by root `cnf.jkt` | `N8aKNGo4023KqM-puSWZHXDMtol87u6100ZO-8PGadw` |
| ai-reconcile-1 | agent instance reconcile-2 | the request; key in WIT `cnf.jwk`, bound by sub-mandate `cnf.jkt` | `5tMZm1nM0jQHv9qvNzz0k-i6rXD4UZIJGjkQsPF8ans` |
| sl-1 | status_issuer | unused here, since no case uses status | `nQMFpQx_-ORFbLEf-liXJQJ8zU2G9xawnwcnwtddhpE` |

These keys are test keys, published with their private parts on purpose.
Never use them for anything else.

Anchor-signed artifacts carry `kid` in the JOSE header. The sub-mandate
carries the ai-treasury-1 public key in `jwk`. The request signature by
ai-reconcile-1 is represented by the PoP outcome input (Section 9.1 item 8),
so no request signature is included.

## Profile

URI `https://bank.example/profiles/agents/3`, as in Appendix A. The digest is
the base64url SHA-256, without padding, of the bytes of `profile/profil.json`:
`ucNBmXOcdTPn2RcRLMmgQBCdfDRnF3r_KofHgRIbFsc`. It matches the published
digest. The file uses sorted member names, no whitespace and no trailing
newline; do not reformat it.

One framework, `https://tf.example/finance`, with `algs` EdDSA only and
`status_required` empty, so an authority case cannot fail for a status reason.
`max_clock_skew` is 60. The profile names the `max_lifetime` artifact types
(`authority`, `mandate`, `wit`, `attestation_result`, `exposure_statement`,
`max_period`) and the Type Profile members (`schema`, `admitted`, `meaning`),
which the draft leaves open. `check.py` reads those names.

## Fixed values

Each case declares its own T as `time` in `inputs.json`. Cases 00 to 03 all
use T = 1792972800, the Appendix A Validation Result time. RP =
`https://bank.example`. PoP outcome `ok` with nonce `vector-nonce-0001`. All
other times are in `decoded.json`.

## Regenerate and check

Python 3.10 or later.

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python check.py             # verifies every case, exits 0 when all agree
venv/bin/python generate.py /tmp/a   # regenerates every case file into /tmp/a
diff -r /tmp/a . | grep -v '^Only in \.:'   # expect no output
venv/bin/python -m unittest discover -s tests   # runs both checks above
```

`generate.py` with no argument writes into this directory. Ed25519 signatures
are deterministic, so two runs produce identical bytes.

`check.py` imports nothing from `generate.py`. It verifies every signature
against `trust-anchors.json` and the key binding chain, runs Section 9.3
steps 1 to 12 as far as these cases need, builds a result, and compares it
with `expected-result.json` as JSON values under Section 4.6 (no
canonicalization; numbers compare by their text, and `true` never equals 1).

## Ambiguities found

1. Sections 9.4 and 9.6: the authority_* codes do not say which artifact, if
   any, they carry. These vectors attach the root mandate's reference.
2. Sections 9.6 and 11: claim `role` values are not enumerated, and the
   sub-delegated mandate is signed by an agent instance key rather than an
   anchor role. These vectors use `agent_instance` for it.
3. Sections 8 and 8.1: the Validation Profile has no defined JSON shape. The
   published profile chooses the `max_lifetime` artifact type names and the
   Type Profile members, and revision -01 is expected to name both.
4. Section 8: which bytes the profile digest covers. The published profile
   digests the file bytes as published, and these vectors follow that.
5. Section 9.1 item 5: the Trust Anchor Set has no defined format.
   `trust-anchors.json` is one possible layout.
6. Sections 4.3 and 9.6: whether Artifact References in the result carry
   `iss` and `jti` hints. Under Section 4.6 identity this changes whether two
   results match. These vectors use `dig` only, as Appendix A does.
7. Section 6.1 and Appendix A: no WIT or operator identifier is given. These
   vectors use `https://treasury.example` and `jti` `wit-reconcile-2-0001`.
8. Sections 9.2 and 9.3: a required assertion that is absent has no code
   other than authority_missing (case 02).
9. Section 9.3: steps run in full after a failure, so `alternatives` is
   listed even when the outcome is invalid. These vectors list it.
10. Section 9.6: an authenticated Authority Assertion that does not support
    the root has its claims left out (case 01), so the RP cannot see the
    powers that caused authority_insufficient.
11. Section 4.6: the rule that numbers are identical only when their text is
    identical is hard to apply to a result that a Validator re-serializes
    (for example `time`).
12. Section 9.1 item 8: the Validator takes the PoP outcome as an input, so
    no PoP proof or HTTP signature is included.
13. Appendix B: the framework_mismatch and `_sd` rows also imply
    authority_insufficient, the same pattern as case 03.

## License

The scripts, tests and generated vectors are under the Apache License 2.0
(see `LICENSE`). `keys/chei.json`, `profile/profil.json` and
`profile/profil.digest` are the draft author's published test inputs,
included unchanged.
