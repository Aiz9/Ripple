---
name: api-recon
description: Use this skill when collecting a website's API endpoints.
mcps: Burpsuite, browser
---

# API Recon (front-end API reconnaissance)

Within an **authorized** scope, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **front-end routes**, and **UI feature triggers** (tabs, dialogs, table actions, etc.).

---

## Boundaries and prohibitions (required reading for agents)

This skill does **API / parameter-surface reconnaissance only**; it is not the vulnerability hunting or exploitation stage.

### Task boundaries

| Area | Allowed | Forbidden |
|---|---|---|
| **Goal** | Enumerate paths, methods, parameters, routes and UI triggers | SQLi/XSS/broken access control/brute force/fuzzing for vulnerabilities, tampering attacks, destructive operations |
| **Authentication** | Hooks + stubs/mocks to bypass the **client-side** login gate | Asking the user for or guessing credentials; submitting the real login form |
| **Runtime** | Hook APIs without credentials and use mock responses to get the SPA into its logged-in shell | Flows that can only continue with a real backend session |

### Credential-free dynamic analysis (Phase 3 default)

1. **Intercept and stub** bootstrap APIs such as login, permissions and menus through `preload.js` / `runtime_harvest.js`;
2. Return mock bodies for business query APIs that are **structurally correct, carry a success business code, and may have empty data**;
3. Make the front end render logged-in pages even with no backend or a 401 environment, triggering more XHR/fetch/WebSocket calls;
4. **Empty data, blank tables and placeholder UI are all expected** -- do not switch to a real login or vulnerability testing because of them.

**In one sentence**: use mocks to open up front-end routes and component mounting and **record only outbound requests**; what the backend returns does not matter, what matters is **which other APIs the front end calls**.

### Hard process prohibitions

| Forbidden | Do this instead |
|---|---|
| grep/curl/Read the main entry `index-*.js` to extract API paths before Phase 1 is done | Run `OUTDIR/harvest_static.py` |
| Hand-write `extract_apis.py` or similar scripts that replace harvest | Modify `OUTDIR/harvest_static.py` and rerun |
| Repeating the same grep/command after it failed 2 or more times | Change strategy: read tool_logs, modify harvest, check the reference |
| Skipping gates A/B and running the original `scripts/` directly | Copy to OUTDIR and adapt to the target |
| Real usernames/passwords, OTP, OAuth or other authentication | Stubs/mocks (see above) |
| Skipping stubs to "get real data" and doing access-control/injection tests | Record outbound only; that is the recon boundary |
| Deletion, exporting sensitive data, bulk writes or other irreversible operations | The same applies to coverage clicks |
| Claiming all pages and APIs were found without completing runtime + dynamic enumeration | See "Definition of done", or state the limitations |
| Claiming all parameters are known without completing the parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Inferring required/optional from a single runtime sample | Multi-sample diff, or infer back from validation rules/errors |

---

## Two-layer model + run modes

| Layer | Output | Limit |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, draft routes, candidate fields at request-assembly sites | No HTTP methods; parameters need Phase 1b; misses URLs assembled at runtime |
| **Runtime** (live session) | Method + body + response + dynamic URLs + WS/SSE; multi-sample diff completes parameters | Pages must actually render to send requests; one sample is not enough to decide required/optional |

| Run mode | Engine | Use |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Click tabs/dialogs/tables for deeper feature coverage |
| **both** | depth first, then coverage | Most complete, takes the longest |

**Parameter methodology** (no generic script): paths come from harvest/regex; parameters from **anchor window expansion + UI binding chain + multi-sample diff + inferring from errors** (grep recipes in section J of [reference.md](reference.md)).

---

## Definition of done

Recon may be declared complete only when all of these hold:

- [ ] **Static**: Phase 1 harvest produced `api_static.txt`, `routes.txt` and `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **working hooks + the dynamic enumeration loop**
- [ ] **Inside the shell**: visiting business paths does not land on `/login` (watch out for hash routes)
- [ ] **Parameters**: coverage/both completed the parameter trigger matrix + `param_samples.json`; Phase 5 merged `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 permission-tree reconstruction and rerun until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs are complete (see the Phase 5 output table); `insert_assets` wrote the service and endpoint assets

---

## Scripts and gates

`scripts/` are reference templates only; running the originals directly and treating that as the final result is **forbidden**.

**Rule**: read first -> adapt to the target -> write into `OUTDIR` (e.g. `recon/`) -> record `CHANGES.md`; if nothing matches, rewrite following the methodology and borrow only the structure.

| Gate | When | Reference script -> OUTDIR copy | Common required changes |
|---|---|---|---|
| **A (static)** | After Phase 0, before the **first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **The default regex runs as-is on most sites**; only change the endpoint regex, webpack/Vite `publicPath`, or MPA exclude/cookie when the manifest/dialect does not match |
| **B (runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success values, stubs, login regex, API prefix, hash/history |

**Mandatory SPA order** (cannot be swapped; Phase numbering takes precedence over "explore first, script later"):

| Step | Must | Forbidden |
|---|---|---|
| After Phase 0 | The next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy the script -> small changes if needed -> **run it immediately** | Extract APIs by hand first, then decide whether to harvest |
| Before Phase 1 is done | Check output with `wc -l`; on 404 fix harvest and retry | Hand-written extract scripts; repeated grep on URLs that were never downloaded |
| From Phase 1b | grep only `OUTDIR/js/*.js` | Using the main bundle instead of harvest |

- ✅ Copy `harvest_static.py` -> (optionally) adjust the regex -> **run immediately**
- ❌ curl the main bundle -> grep many times -> write a throwaway extractor -> only then harvest
- **MPA**: after Phase 0 the next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and output constraints

| Constraint | Notes |
|---|---|
| Large files | `index-*.js` files >100KB must **never** be Read/grepped into the context; batch-process them with OUTDIR scripts |
| grep output | Must use `\| head -20` or `-m 5`; keep only path summaries in the conversation, never paste bundle fragments |
| Checks | Use `wc -l`, `ls \| wc -l`; never Read a whole directory |
| Exploratory regex | Optional, at most once, only on small chunks or HTML <=50KB; the formal static result comes from harvest |
| reference | Recipes/templates/troubleshooting are in [reference.md](reference.md); do not repeat them inline in full |

---

## Execution roadmap

```
Phase 0 classify + OUTDIR
  -> Gate A -> Phase 1 harvest (* run immediately *)
  -> Phase 1b parameter reverse engineering
  -> Phase 2 three authentication gates -> config.json
  -> Gate B -> Phase 3 runtime + parameter matrix
  -> Phase 4 permission tree (when needed) -> rerun Phase 3
  -> Phase 5 merged report + insert_assets bulk-inserts every discovered service and endpoint API asset; no discovered asset may be left out
```

Tick them in order; **do not enter the next phase until the previous item is done**.

1. [ ] **Phase 0**: probe SPA/MPA; create `OUTDIR` -> [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy scripts -> harvest **immediately** -> check with `wc -l` -> [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor window expansion + binding layer -> `param_candidates.json` -> [Phase 1b](#phase-1b--parameter-reverse-engineering)
4. [ ] **Phase 2**: three authentication gates -> `config.json` -> [Phase 2](#phase-2--three-authentication-gates)
5. [ ] **Gate B**: adapt the runtime scripts -> [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm you are inside the shell; parameter trigger matrix -> `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree -> patch stubs -> rerun Phase 3 -> [Phase 4](#phase-4--permission-tree-reconstruction)
8. [ ] **Phase 5**: merge outputs + report + `insert_assets` -> [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 — Classification

Fetch the entry HTML and **create `OUTDIR`** (do not modify the skill's own `scripts/`):

- **SPA**: empty shell + `<div id=app>` + chunks -> Phases 1-5
- **MPA**: SSR + `<form>`, no endpoint bundle -> after gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt` and `api_inline.txt`. If an SPA has forms ~ 0 -> switch to Phase 1.

---

## Phase 1 — Static

Follow [Scripts and gates](#scripts-and-gates) and [Tool and output constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parse HTML scripts -> webpack/Vite manifest -> download every lazy chunk -> produce `js/`, `api_static.txt`, `routes.txt` and `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- Chunk count vs. manifest: on 404, fix harvest and retry; never curl chunks one by one by hand
- Too few entries in `api_static.txt` -> loosen the endpoint regex in OUTDIR and rerun (see the reference)

### Phase 1b — Parameter reverse engineering

Paths come from Phase 1; parameter fields need their own recon. grep rules are in [Tool and output constraints](#tool-and-output-constraints).

**Done when**: for the important APIs you can answer field name, transport location, inferred type, whether it is required, sample value and confidence.

#### 1b.0 — Transport shape

| Shape | Where the parameters are | What to check first statically |
|---|---|---|
| REST JSON | body + query | Next to the path anchor: `(params\|data\|body)\s*:\s*\{` |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Classic form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameters | `/user/:id` | Route tables + `useParams` / `$route.params` |
| Encryption/signing | Wrapped into `sign`/`data` | Hook the encryption function's arguments (reference section D) |

Output: tag each API with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor window expansion

Using known paths as anchors, widen the window to find the object that assembles the request:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clues |
|---|---|
| axios instance | `data` / `params` |
| Unified request helper | Global fields injected by interceptors |
| OpenAPI client | Generated method signatures |
| React Query / SWR | The hook's second argument |
| Vue composable | The composable's arguments |

Type leftovers: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

-> `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding layer

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| Form submit | Follow submit -> transform -> API |
| Table search | `getFieldsValue()` -> `params` |
| Routes | `:id` / `?tab=` |
| Interceptors | Global `tenantId`, paging, sign |
| Enum select | `options` -> API enum values |

In the DevTools call stack, trace upward from `fetch`/`XHR.send` to the request-assembly function.

#### 1b.3 — Three request-assembly questions (not the same as Phase 2's three authentication gates)

| Question | What to answer |
|---|---|
| **Assembly** | Where the payload is built, and traces of transforms |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also reads globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 — Hand-off to Phase 3

Candidate fields come from the static/binding layer; **required/optional/conditional dependencies** need the Phase 3 parameter matrix + diff + Phase 5 inference from errors.

---

## Phase 2 — Three authentication gates

grep in `OUTDIR/js/` (with `head`) and write `config.json` (recipes in the reference):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How does it decide you are logged in? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Never treat a localStorage key name as a credential -- confirm it from chunks/the request chain.

**Exit = gate B**: the conclusions go into `config.json`, and `OUTDIR/runtime_harvest.js` / `preload.js` are adapted.

### Phase 2b — API observation (optional)

Use `preload.js` in OUTDIR to confirm session key names, Authorization and nested API URLs:

| Setting | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | Header observation |
| `extractUrlsFromResponse: true` | Sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | Backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

coverage exports each round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Gate B must be passed; follow [Boundaries and prohibitions](#boundaries-and-prohibitions-required-reading-for-agents) and the credential-free mock strategy.

Set `"runtimeMode": "depth" | "coverage" | "both"` in `config.json` (template in the reference).

### Hooks and stubs (shared by depth and coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 exact | Auth/permission/bootstrap stubs | Get past first-screen authentication |
| L2 negative correction | Every JSON response | Not-logged-in code -> success |
| L3 fallback | `/api` etc. not matched by L1 | Empty success body to open up the UI |

- **depth**: fake auth + `forward` rewrites business codes + `stubs`; walk `routes` (hash/history); produces `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or a userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; business paths do not bounce back to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — coverage dynamic enumeration (mandatory)

1. Main navigation/sidebar -- click every item and wait 1-3s for the network
2. Tabs -- `role=tab`, `.ant-tabs-tab`
3. Tables -- view/edit/details on the first row
4. Toolbar -- export, filter, create (**avoid irreversible deletes**)
5. On entering each module -- merge APIs/routes
6. SPA -- controlled `pushState` to paths in `routes.txt` not yet covered (forbidden for MPA)

**Parameter trigger matrix** (mandatory): record each module once per operation type and **diff the samples**:

| Operation | Parameters it usually adds |
|---|---|
| List first screen | Paging + default filters |
| Click search | keyword, filter |
| Advanced filter | More optional parameters |
| Create/edit | The complete entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs the outbound body/headers are still real** -- the request is what counts. Record into `scan_raw.json`, `param_samples.json` and `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: 3a depth first, then 3b coverage

---

## Phase 4 — Permission tree reconstruction

**Trigger**: module pages are blank / every route only has bootstrap calls (such as locale) -> the content gate was not passed.

| Symptom | Meaning |
|---|---|
| Inside the shell | Render gate + interceptor gate passed |
| Sidebar items missing / clicks show blank pages | Stub shape or permission codes incomplete |
| Every route has the same, very few APIs | `v-if permission` not satisfied |
| `routes.txt` far smaller than the bundle | Must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) -> `getResultTree` -> `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: the outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers every link in `route_map`.

After updating `config.json`, **rerun Phase 3**. Large SPAs can tune `waitUntil`, `routeTimeout` and `perRouteMs` (see reference sections A3/I).

---

## Phase 5 — Merge and report

### Output table

| File | Phase | Content |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | Static bundles and paths |
| `param_candidates.json` | 1b | Static parameter field candidates |
| `config.json` | 2 | Three gates + runtime config |
| `runtime_api.json` | 3a | Detailed depth recording (including WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | Multiple samples, click log, details |
| `route_map.json` etc. | 4 | Permission-tree intermediate files (if run) |
| `params_merged.json` | 5 | Merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | Routes, APIs, params, features, limitations |
| **insert_assets** | 5 | Write every service and endpoint asset into the asset store |

### 5b — Parameter merging

Diff from `param_samples.json`; **there is no generic merge script**. Confidence rules are in reference J7 (high/medium/low/to be triggered).

### 5c — Inferring from errors

Within the authorized scope you may send incomplete requests to read 400 responses (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Watch out for `data` wrappers, `variables`, and pre-encryption `bizData`.

The report must state: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary relative to the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

More fields and grep recipes are in [reference.md](reference.md).

---

## General notes

- **Framework-agnostic**: webpack/Vite/Angular lazy loading works the same way
- **Transport**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetches can be recorded; RSC/Server Actions cannot be fully enumerated
- **Blind spots**: JSVMP, WASM, strict HMAC/mTLS checks -> static + state the limitations
- **Parameter blind spots**: conditional linkage, hidden params, WASM request assembly -> "to be triggered" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static analysis can still enumerate endpoints

---

## Additional resources

- Grep recipes, `config.json` templates, troubleshooting, hooks, parameter reverse engineering (section J), site_map template: **[reference.md](reference.md)**
- Reference script paths are in the [Scripts and gates](#scripts-and-gates) table
