# API

Smoke listen address: `:8093`. Health `service` id: `osa-api`.

## Health

`GET /api/health` → `{"status":"ok","service":"osa-api"}`


## Tenant directory + GitHub discovery

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/hub/organizations` | Proxy hub tenancy orgs (`PEER_OPA_URL`) |
| GET | `/api/oam/projects` | Proxy OAM projects (`PEER_OAM_URL`); `?organization_id=` and `?product=osa` filter (enabled-only for that product) |
| GET | `/api/hub/github/status` | Hub GitHub status + OSA peer config |
| GET | `/api/github/connectors` | Proxy ORA connectors (`PEER_ORA_URL`) |
| GET | `/api/github/connectors/{id}/repos` | Proxy ORA repo list |
| GET | `/api/security/targets` | Discovery model summary for the dashboard |
| GET | `/api/services` | Service names this tenant's security corpus is filed under |

These two routes back the dashboard's tenant picker. OSA owns neither directory:
organizations come from the hub (which fronts OAM for peers via its `oamdir`
package), and projects come straight from OAM because no peer-facing projects
route exists upstream.

Both upstreams key rows as `id`. Each row is returned with the dashboard's field
name **added** alongside it — `org_id` on organizations, `project_id` on projects —
so `id` stays valid for existing callers:

```json
{"organizations":[{"id":"acme","org_id":"acme","agent_count":0,"source":"oam"}]}
{"projects":[{"id":"web","project_id":"web","organization_id":"acme","name":"Web"}]}
```

`organization_id=all` is dropped rather than forwarded: `all` is the tenant-header
sentinel for "unscoped", while OAM's filter is a concrete-id predicate, so passing
it through would return zero projects on the selection meant to widen the list.

`product=osa` (or another family code) forwards to OAM so the picker only lists
projects that are not in that product's `disabled_products` denylist. Enablement
writes stay on OAM Dashboard → oam-api (no peer write proxy).

Job/scan fail-closed hook: before starting a scan for a concrete OAM directory
id, call `GET /api/oam/projects?product=osa` (or OAM directly) and reject when
the id is absent; skip when `PEER_OAM_URL` is unset or the project header is
empty/`all`.

With `PEER_OAM_URL` unset, `/api/oam/projects` returns an empty list plus
`peer_unavailable: true` — the picker is empty, not broken.

### `GET /api/services`

Backs the Service field on the scan form. Tenant-scoped, aggregated across
`security_runs` and every findings table that carries a `service` label — CI can
ingest findings via `/v1/security/*` with a service name and no run id, so runs
alone would miss services that have findings:

```json
{"services":[{"name":"php-smoke","runs":1,"findings":3,"last_seen":"2026-08-05 12:41:07.881"}]}
```

Each source table is queried independently and a table that cannot be read is
skipped, not fatal. When that happens the response also carries
`unavailable_tables` and a `note`, because a short list from a missing table is
otherwise indistinguishable from a genuinely short list.

## Security runs

Create body (GitHub primary):

```json
{
  "connector_id": "conn-…",
  "repo_full_name": "owner/repo",
  "ref": "main",
  "profile": "auto",
  "scanners": ["secrets", "sast"],
  "dispatch": true
}
```

`connector_id` + `repo_full_name` trigger an ephemeral clone via ORA. Omit both to fall back to `target_path` under `OSA_SECURITY_WORKSPACE`.

## Security runs

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/security/profiles` | Scanner profiles (`auto`, `php`, `node`, …) |
| GET/POST | `/api/security/runs` | List / create security runs (`connector_id` + `repo_full_name` preferred) |
| POST | `/api/security/runs/batch` | Create up to 50 runs for `repos[]` with shared connector/profile/scanners |
| GET | `/api/security/runs/{id}` | Run detail |
| GET | `/api/security/runs/{id}/findings` | Findings for a run |

### Repository scores (internal)

Finished security runs still update durable **repo score** rollups in ClickHouse
(`repo_security_scores`). There is **no** public `GET /api/security/repos` API
(plain **404**).

Composite score is the arithmetic mean of **per-scanner facets** in
`{secrets, sast, iac, cve, container}` (`sbom` is inventory-only and excluded).

Each scanner facet:

```
max(0, 100 - 25*blocker - 20*critical - 10*high - 4*medium - 1*low)
```

(info ignored). A run that executes only one scanner updates **only that facet**;
other scanners keep their previous scores and `run_id`s. Unmeasured scanners are
omitted from the mean.

### `POST /api/security/runs/batch`

```json
{
  "connector_id": "conn-…",
  "repos": ["owner/a", "owner/b"],
  "ref": "main",
  "profile": "auto",
  "scanners": ["secrets", "sast"],
  "dispatch": true
}
```

Response `200` (all ok), `207` (partial), or `400` (none created):

```json
{
  "runs": [{"repo_full_name": "owner/a", "id": "srun-…", "status": "queued"}],
  "errors": [],
  "total": 2,
  "ok": 1,
  "failed": 0
}
```

Batch size is capped at **50**.


### `GET /api/security/runs` — list query params

| Param | Default | Range | Notes |
|-------|---------|-------|-------|
| `limit` | `50` | `1`–`200` | Values above `200` are **silently clamped** to `200`. There is no `offset` or cursor; the handler returns the most recent rows by `started_at DESC` for the active tenant only. |

Response shape: `{"runs":[…],"workspace":"…"}`. No `total`, `has_more`, or `limit_applied` metadata — clients cannot page past the cap without a future API change.

Tenant headers **`X-Organization-ID`** / **`X-Project-ID`** scope lists when `OPA_AUTH_REQUIRED=1` (NAS). Omitting them (or sending `"all"`) scopes to **`default-org` / `default-project`**, matching writes (Open-Tenant-Go ≥ 0.2.2). Same pattern applies to inventory routes such as `GET /api/security/secrets` and `GET /api/security/sast`.

**NAS example** (hub JWT; no headers → default-org rows; wrong org → empty; `limit=500` still capped at 200):

```bash
TOKEN=$(curl -sf -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .token)

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.runs | length'

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=500" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: default-org" \
  -H "X-Project-ID: default-project" | jq '.runs | length'   # → ≤200

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=5" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: no-such-org" \
  -H "X-Project-ID: no-such-project" | jq '.runs | length'   # → 0
```

## AppSec inventory + ingest

| Method | Path |
|--------|------|
| GET | `/api/security/secrets` |
| GET | `/api/security/sast` |
| GET | `/api/security/iac` |
| GET | `/api/security/containers` |
| GET | `/api/security/policies` |
| POST | `/v1/security/secrets` |
| POST | `/v1/security/sast` |
| POST | `/v1/security/iac` |
| POST | `/v1/security/containers` |

CI ingest uses `OSA_SECURITY_INGEST_TOKEN` via `Authorization: Bearer` or `X-OSA-Security-Token`.

## AppSec gate

| Method | Path |
|--------|------|
| GET/POST | `/api/security/gate` | Fail-closed on secrets/SAST/IaC severity for `security_run_id` |

Distinct from ORA **review** check-runs.

### Documentation placeholders

Secret detection filters values that are visibly stand-ins **and** live in
documentation or an example configuration file. Both conditions must hold:

| Condition | Matches |
|-----------|---------|
| Path | `docs/`, `doc/`, `documentation/`, `examples/`, `samples/` at any depth; `*.md`, `*.mdx`, `*.rst`, `*.adoc`, `*.txt`; `*.example`, `*.sample`, `*.template`, `*.dist`, `*.tpl` |
| Value | `your-…`, `changeme`, `replace-me`, `placeholder`, `example`, `dummy`, `redacted`; `${VAR}`, `{{ var }}`, `<token>`, `__VALUE__`; a value that only names its field (`PASS=password`); four or more repeats of one character (`xxxxxxxx`) |

So `OPA_SMTP_PASS=your-smtp-password` in a documentation page does not fail the
gate, while a real credential pasted into the same page still does, and nothing
is relaxed for source files. Filtered matches are counted in the run summary as
`secrets_filtered_fp` rather than dropped silently.

The rule is enforced once, in the finding ingest path, so the full engine and the
embedded lite scanner agree. It is deliberately **not** a `gitleaks.toml` path
allowlist: those apply unconditionally, so a `docs/` glob would also silence a
real credential committed to a documentation page.

## Vulns / IAST

| Method | Path |
|--------|------|
| POST | `/v1/sbom` |
| GET | `/api/vulns/summary` |
| GET | `/api/vulns/findings` |
| GET | `/api/vulns/inventory` |
| GET | `/api/iast/summary` |
| GET | `/api/iast/findings` |

## Peer probe

`GET /api/peer/health` — validates service JWT (`aud=osa-api`, scope `health:read`) when `OPEN_SERVICE_JWT_SECRET` is set.

## SCM checker peer

`POST /api/peer/scm/events` — ORA fan-out entry for the **`dependencies`** checker (lockfile CVE via OSV). Service JWT: `iss=ora-api`, `aud=osa-api`, scope **`scm:events`**. Request/response fields match [OPA-Stack interop — SCM checker platform](https://github.com/TheGrimmChester/OPA-Stack/blob/main/docs/interop.md#peer-contract-post-apipeerscmevents). See [configuration.md](configuration.md#scm-checker-peer-post-apipeerscmevents) for trigger rules and env tuning (`OSA_CVE_*`).

## Peer-callable AppSec routes

These accept **either** a user JWT (viewer+) or a service JWT (`aud=osa-api`) minted
with `OPEN_SERVICE_JWT_SECRET`. `ora-api` calls them to delegate AppSec; every other
route is user-JWT-only.

| Route | Read scope | Write scope |
| --- | --- | --- |
| `/api/security/runs` | `findings:read` | `runs:write` |
| `/api/security/runs/{id}` | `findings:read` | `runs:write` |
| `/api/security/gate` | `findings:read` | `findings:read` (POST is a read) |

A service JWT presented to a user-only route fails `ParseUserJWT` and returns
**401 `invalid token`** — matching secrets on both sides do not help. If `ora-api`
logs `peer OSA security run failed` / `peer OSA gate failed` with that 401, check
this wiring before suspecting secret drift.
