# Security policy

## Supported version

Security fixes target the latest `main` branch until a stable release line is announced.

## Report privately

Do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting in
`alexar76/basanos` and include the affected revision, reproduction, impact, and a
minimal non-sensitive proof.

Never include provider seeds, Hub publish tokens, or contract private keys in a report.

## When a pack is not PASS (ISO/IEC 29147 / 30111)

BASANOS does not contain, patch, slash, or disclose. It emits a signed playbook
on the pack (`handling`) and stops there.

| Verdict | NIST SP 800-61 phase | Operator does | BASANOS does not |
|---|---|---|---|
| **FAIL** (high / critical) | Containment | Stop shipping this digest. Pause on-chain only if you already control a pause path. Private notify. Patch, re-scan, then disclose. | Send `pause()`, `coverListing`, or a public exploit |
| **REVIEW** (medium) | Detection & analysis | Human verification. No `coverListing` until confirmed or dismissed. | Admit/reject the Hub listing |
| **PASS** (low / info / clean) | Post-incident / backlog | Record the digest. Coverage is still a human economic decision. | Authorize AgentAuditPool cover |
| **NO_SUBJECT** (nothing read) | — | Fix the request, not the code: name a root that exists (`fixtures` always does) or set `BASANOS_CONTRACT_ROOT`. Do not record the digest as assurance. | Judge, grade, or clear anything — it read no Solidity |

Coordinated disclosure (same windows as the factory policy): acknowledge within **72 hours**,
up to **90 days** before a public write-up. Findings are static-analysis **candidates** until a
human verifies them. Do not attach a proof-of-concept to a public issue.

## Trust boundaries

- `/invoke` input (`roots`, `ingest_intel`) is untrusted. Callers name inventory ids, never filesystem paths.
- Solidity is read as text. The service never compiles with solc, never executes bytecode, and never
  fetches URLs found in source comments (no SSRF).
- Threat intel is opt-in (`BASANOS_THREAT_INTEL=1`), allowlisted (`api.osv.dev`, `api.github.com`),
  fail-closed in production unless `BASANOS_THREAT_INTEL_PROD=1`. Redirects are refused. Advisory
  text is DATA: it may reorder detectors, never add one, never emit `scoreBps`.
- `/invoke` rejects bodies larger than 65 KiB, duplicate JSON keys, and unknown model fields.
- Ed25519 signatures bind a pack to the exact decoded input and provider identity.
- A signed pack proves which provider produced that pack for a specific tree digest. It does not
  prove the contracts are safe on-chain, and it is not AgentAuditPool cover.

## Deployment checklist

1. Keep the container port on loopback or a private network.
2. Put an authenticated HTTPS ingress or AIMarket Hub in front of `/invoke`.
3. Mount one persistent `/data/provider.key`; never bake the seed into an image.
4. Back up the key before publishing `provider_pubkey`.
5. Apply an external request rate limit.
6. Pin the image digest and rerun the test suite before deployment.
