# dsh-daiyi-aimy-skill

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="package.json"><img alt="Node" src="https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg"></a>
  <a href="package.json"><img alt="DSH" src="https://img.shields.io/badge/DSH-%3E%3D0.2.0--rc.1-6f42c1.svg"></a>
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-0-success.svg">
  <a href="https://github.com/zxz0119/aimy-sikll"><img alt="upstream" src="https://img.shields.io/badge/upstream-aimy--sikll%20v2.0.0-orange.svg"></a>
  <a href="README.zh.md"><img alt="中文" src="https://img.shields.io/badge/docs-中文-lightgrey.svg"></a>
</p>

> **Authorized-scope reconnaissance and web vulnerability detection for DeepSeek Harness: 8 native tools + 8 skills, deny-by-default, detection only.**

`dsh-daiyi-aimy-skill` is a **DeepSeek Harness (DSH) Cordis plugin** redeveloped from [zxz0119/aimy-sikll](https://github.com/zxz0119/aimy-sikll) (Python CLI, v2.0.0). It turns the upstream command-line scripts into resident native tools and adds something upstream never had: an **authorization-scope gate**. With no registered scope, no network tool will run.

- Shape: ESM Cordis plugin, **zero runtime third-party dependencies** (only `node:` built-ins).
- Host: DSH `>=0.2.0-rc.1 <0.3.0`; Node `^22.19 || >=24`.
- Version: `3.0.0`, MIT, by 戴亿.

## Features

| Feature | Description |
|---|---|
| **8 model-callable tools** | scope, recon, ports, directory fuzzing, crawling, web scanning, JWT audit, reporting |
| **Deny-by-default** | Every network target must be registered through `aimy_scope`; unregistered targets are refused with a hint |
| **Authorization records & audit** | Each scope entry requires a written authorization note (≥ 8 chars), optional expiry, and audit-logged changes |
| **12 detection + 3 recon modules** | Detection: sqli / xss / cmdi / ssti / ssrf / nosqli / lfi / cors / jwt / graphql / proto-pollution / headers; recon: crawler / param-miner / tech-fingerprint. Port and directory probing live in the tool layer |
| **Single network egress** | All requests go through the guarded probe in `lib/http.js`: per-request scope check, budget, timeout, body cap, redirect re-check |
| **8 Chinese skills** | authorized scope, recon workflow, web triage, auth & JWT, API & GraphQL, reporting, rookie mode, veteran mode |
| **Three report formats** | Markdown / JSON / SARIF, redacted by default |
| **Zero runtime dependencies** | No `requests`, no third-party HTTP client; host provides `dsh-tools` and `dsh-skill` |
| **Detection only** | No reverse shells, deserialization exploit chains, SSRF pivoting, OOB callbacks, or WAF bypass |
| **No UI panel** | Tools, skills and report files only; there is no graphical interface |

## Install

Prerequisites: DSH desktop (`>=0.2.0-rc.1 <0.3.0`) and Node `^22.19 || >=24`. No build step and no runtime dependencies.

### Option A: DSH plugin manager (recommended)

Open DSH desktop **Settings → Plugins** and use the plugin manager to install either:

- **A local directory**: point it at this repository (which contains `package.json` and `cordis.patch.yml`).
- **A git repository**: `https://github.com/DaiYiqq/dsh-daiyi-aimy-skill`.

After install, the plugin manager's reconcile reads this package's `dsh.bundle.patch` and adds the `cordis.patch.yml` insert entry (`id: daiyi-aimy-skill`) to the profile.

### Option B: manual plugin directory

1. Put this directory under your DSH plugins directory (e.g. `~/.dsh/plugins/dsh-daiyi-aimy-skill`).
2. Add it to the profile's `package.json` dependencies:

   ```json
   {
     "dsh-daiyi-aimy-skill": "file:~/dsh/plugins/dsh-daiyi-aimy-skill"
   }
   ```

   > The part after `file:` must be an **absolute path** on your machine; the `~/...` above is illustrative.
3. Run `pnpm install` in the profile directory.
4. Restart / reload DSH. Because this package declares `dsh.bundle.patch`, the plugin manager's reconcile adds the package name to `dsh.profile.bundles`.

When loaded, the session exposes 8 `aimy_*` tools and 8 `aimy-*` skills.

## Quick start (5 lines)

```text
// Step 1: register the authorized scope — without it every network tool refuses
aimy_scope(action="add", target="example.com", authorization="Client authorization letter #A-1024, scope: example.com", expiresInHours=72)
aimy_recon(target="https://example.com")
aimy_crawl(target="https://example.com/", maxPages=10)
aimy_web_scan(target="https://example.com/search?q=test", checks=["xss", "sqli"])
aimy_report(action="report", format="md", outputPath="reports/example-com.md")
```

A full tool-call result (truncated):

```json
{
  "target": "https://example.com/search?q=test",
  "checks": ["xss", "sqli"],
  "skipped": [],
  "params": [{ "name": "q", "location": "query", "sample": "test" }],
  "findings": [
    {
      "module": "xss",
      "checkId": "xss-reflected",
      "title": "Reflected XSS (HTML context)",
      "severity": "high",
      "confidence": "high",
      "url": "https://example.com/search?q=test",
      "param": "q",
      "payload": "aimy1337<script>alert(1)</script>",
      "evidence": "Parameter q was reflected verbatim in an HTML context; the payload appeared unencoded in the response (200).",
      "cwe": "CWE-79",
      "remediation": "Apply context-aware HTML/attribute/JS encoding, allowlist filtering, and CSP as defense in depth."
    }
  ],
  "requests": 9,
  "notes": ["runId=run-1a2b3c4d", "mode=rookie"]
}
```

> The finding above only illustrates the field shape; it does not claim that `example.com` has this issue. Actual output depends on your target and config.

## Tools

| Tool | Purpose | Requires scope |
|---|---|---|
| `aimy_scope` | Add / list / remove / clear authorized scope; dry-run a target | No (it is the gate) |
| `aimy_recon` | DNS, HTTP baseline, security headers, tech fingerprint, robots.txt | Yes |
| `aimy_port_scan` | TCP connect port probe (handshake only), risky-port findings | Yes |
| `aimy_dir_fuzz` | Path enumeration with soft-404 baseline and sensitive-path findings | Yes |
| `aimy_crawl` | Same-origin crawl: pages, links, forms, params, JS endpoints | Yes |
| `aimy_web_scan` | Run a set of web checks (12 check types) against one URL | Yes |
| `aimy_jwt_audit` | Offline JWT audit: alg, weak secrets, claims, external key sources | No (local only) |
| `aimy_report` | Summarize, list findings, export Markdown / JSON / SARIF | No |

Full parameter tables, return shapes, error codes and limits: [docs/TOOLS.md](docs/TOOLS.md).

## Skills

| Skill | When to load |
|---|---|
| `aimy-authorized-scope` | Session start, target change/expansion, or a `NO_SCOPE` / `NO_MATCH` / `EXPIRED` / `PRIVATE_BLOCKED` result |
| `aimy-recon-workflow` | Scope registered and you need the asset map: hosts, ports, directories, pages, params, tech |
| `aimy-web-vuln-triage` | You have a parameterized URL and must decide if a web finding is real and how severe |
| `aimy-auth-and-jwt` | Login state, Bearer tokens, JWTs, session or object-level authorization questions |
| `aimy-api-and-graphql` | `/api`, `/graphql`, `/swagger` style interfaces exist |
| `aimy-finding-report` | A scan round is done and you need a report or CI-ready SARIF |
| `aimy-rookie-mode` | Beginners, production targets, or `mode=rookie` |
| `aimy-veteran-mode` | Clear authorization, staging/lab targets, higher coverage and chained checks |

Skills are **method guidance**: they do not auto-run tools and cannot bypass `aimy_scope`.

## Upgrade from upstream

| Dimension | Upstream `aimy-sikll` v2.0.0 | This plugin v3.0.0 |
|---|---|---|
| Shape | Python CLI, `python main.py <subcommand>` | DSH Cordis plugin, tools called by the model |
| Authorization | Input a target, start probing | Deny-by-default; register scope first |
| Network egress | Each module uses `requests` freely | Single guarded probe with per-request scope checks |
| Output | JSON printed to the terminal | Structured returns + three report formats |
| Dependencies | `requests`, etc. | Zero runtime third-party deps |
| Session | `.pkl` session files | Stateless; no credential storage |
| Concurrency | Thread pool | Bounded concurrency + request budget + cancellation |
| Weaponization | Present (reverse shells, data dumping, pivoting, …) | **Not provided**; those modules are not ported |
| Skills | 101 Markdown files | Curated into 8 executable playbooks |

See [docs/MIGRATION.md](docs/MIGRATION.md) for the per-module disposition of all 34 upstream files (ported / merged / partially absorbed / not ported, with reasons) and the CLI-to-tool mapping.

## Configuration

Configuration comes from `cordis.patch.yml` `config`, merged with defaults; invalid values fall back and produce warnings.

```yaml
- insert:
    - id: daiyi-aimy-skill
      name: dsh-daiyi-aimy-skill
      config:
        mode: rookie
        persistScope: true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `rookie` \| `veteran` | `rookie` | Runtime mode; changes budgets and payload aggressiveness only, never the authorization boundary |
| `persistScope` | boolean | `true` | Persist scope to disk; `false` keeps it in memory only |
| `scopeFile` | string | `<DSH_HOME>/daiyi-aimy-skill/scope.json` | Scope file path |
| `timeoutMs` | number | 8000 (rookie) / 12000 (veteran) | Per-request timeout, max 60000 |
| `maxRequests` | number | 24 / 60 | Per-tool-call request budget, max 400 |
| `concurrency` | number | 4 / 8 | Concurrency cap, max 32 |
| `maxBodyBytes` | number | 262144 | Response body cap, max 4 MiB |
| `followRedirects` | boolean | `false` | Do not follow redirects by default |
| `maxRedirects` | number | 3 | Max hops when following |
| `userAgent` | string | `dsh-daiyi-aimy-skill/3.0.0 (...)` | Default UA; targets can identify the tester |
| `allowPrivateNetworks` | boolean | `false` | Allow loopback/private targets in scope |
| `redactSecrets` | boolean | `true` | Redact suspected credentials in reports |
| `maxFindings` | number | 800 | In-memory finding cap |
| `maxRuns` | number | 60 | In-memory run-record cap |

## Security & compliance

- **Detection only**: no reverse shells, deserialization exploit chains, SSRF pivoting, OOB callbacks, WAF bypass, data extraction, credential attacks, or MITM credential capture.
- **Deny-by-default**: with no scope, every network tool refuses; each scope needs a written authorization note.
- **Constrainable scope**: `host`, `host:port`, scheme, `*.` subdomain wildcards, path prefixes and expiry; loopback/private targets are blocked by default.
- **No credential storage**: the plugin does not persist tokens, cookies or sessions; scope files contain no credentials.
- **No detection-rate promises**: checks are response-difference heuristics and can miss or false-positive; a human with authorization must review conclusions.
- **Lawful use**: only against targets with **written authorization**. Unauthorized probing, data extraction, persistence and denial of service are prohibited and outside the plugin's capabilities.

Full authorization model, matching rules and reporting channel: [docs/SECURITY.md](docs/SECURITY.md).

**Reporting a vulnerability in this plugin**: prefer a GitHub Security Advisory or email `1703205607@qq.com`; please do not disclose details before a fix.

## Repository layout

```text
dsh-daiyi-aimy-skill/
├── lib/
│   ├── index.js            # plugin entry: name / inject / apply
│   ├── config.js           # config normalization and mode budgets
│   ├── scope.js            # authorization scope: parse, match, persist, audit
│   ├── http.js             # guarded HTTP probe (single network egress)
│   ├── store.js            # findings store, dedupe, run records
│   ├── report.js           # Markdown / JSON / SARIF renderers
│   ├── tools/              # 8 model-callable tools
│   ├── engine/             # detection modules + catalog
│   └── skills/             # skill loader
├── skills/                 # 8 aimy-* skills (SKILL.md)
├── docs/                   # TOOLS / MIGRATION / SECURITY / ARCHITECTURE / CONTRACT
├── scripts/                # validate-plugin.mjs contract checks
├── test/                   # contract, engine and skill tests
├── cordis.patch.yml
├── package.json
├── README.md / README.zh.md
├── CHANGELOG.md
└── LICENSE
```

## Development & testing

Node `^22.19 || >=24`. **Zero third-party dependencies**, so `npm install` is not needed.

```bash
npm run check     # contract validation + node --check lib/index.js
npm test          # node --test "test/**/*.test.js" (recursive)
npm run verify    # check + test (what CI runs)
```

Check a single file:

```bash
node --check lib/http.js
node --test test/engine/sqli.test.js
```

CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) — `ubuntu-latest` + Node 24, runs only `npm run verify`, no extra install steps.

Design notes and how to add a detection module: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

[MIT](LICENSE) © 2026 戴亿 <1703205607@qq.com>

Upstream `aimy-sikll` is also MIT-licensed. This plugin is an independent redevelopment, not an official upstream release.
