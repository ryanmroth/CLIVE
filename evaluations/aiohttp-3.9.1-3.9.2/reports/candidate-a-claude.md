I audited `aiohttp/web_urldispatcher.py` (v3.9.1) in full, plus the local paths needed to establish provenance and reachability: `http_parser.py` (request-target parsing), `web_request.py` (`rel_url`/`url`/`clone`/`http_range`), `web_app.py` (`add_subapp`/`add_domain`), `web_fileresponse.py` (the `StaticResource` sink), and `web_middlewares.py` (`normalize_path_middleware`, the only local path-normalization code).

**Key provenance fact established from source, on which several findings rest:** aiohttp does *not* perform RFC 3986 dot-segment removal on the request target. `HttpRequestParser.parse_message` builds the URL with `URL.build(path=path_part, ..., encoded=True)` (`<EVAL_WORKSPACE>/candidate-a/aiohttp/http_parser.py:592-597`), and `BaseRequest._rel_url` takes that object verbatim (`web_request.py:185`). `normalize_path_middleware` only merges slashes and adjusts trailing slashes, and only runs after routing already failed (`web_middlewares.py:78`). Therefore `request.rel_url.raw_path` — the value every `resolve()` in this file matches against — can contain literal `../` segments supplied by the client.

---

### [HIGH] Path traversal in `StaticResource` when `follow_symlinks=True` (SCA-001)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:665-667` in `StaticResource._handle()`
**Also at**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:599-601` in `StaticResource.url_for()`
**Classification**: OWASP A01:2021-Broken Access Control · CWE-22 (this is CVE-2024-23334, fixed upstream in 3.9.2)
**Confidence**: High (complete source-to-sink path traced; the only runtime-dependent element is noted below)

**Attack Path**: `GET /static/../../../etc/passwd` → `HttpRequestParser.parse_message` (`http_parser.py:592`, `encoded=True`, no dot-segment removal) → `BaseRequest._rel_url` (`web_request.py:185`) → `UrlDispatcher.resolve` (`web_urldispatcher.py:1011`) → `StaticResource.resolve` (`:641`, prefix check passes because the path *does* start with `/static/`) → `match_dict["filename"] = "../../../etc/passwd"` (`:647`) → `StaticResource._handle` (`:657`) → `self._directory.joinpath(filename).resolve()` collapses the `..` segments (`:665`) → containment check skipped at `:666` → `FileResponse(filepath)` (`:690`) → arbitrary file contents returned.

**Description**: The containment check is gated on the configuration flag:

```python
filepath = self._directory.joinpath(filename).resolve()
if not self._follow_symlinks:
    filepath.relative_to(self._directory)
```

`follow_symlinks=True` is documented as "permit symlinks out of the static root," but in this code it disables the *only* boundary check on the resolved path. Because `Path.resolve()` normalizes `..` before any check occurs, and because the prefix test at `:641` runs against the un-normalized raw path (so `/static/../..` still looks like it is under `/static/`), the traversal is unconstrained. The `filename.anchor` guard at `:660` only blocks *absolute* paths (`/etc/passwd`, `C:\`, UNC) — it does nothing against relative `..` traversal.

**Impact**: Unauthenticated arbitrary file read across the entire filesystem readable by the server process: application source, `.env` files, private keys, `/proc/self/environ`, cloud instance credentials. With `show_index=True` it additionally becomes arbitrary directory enumeration (see CHAIN-001).

**Provenance / precondition**: `follow_symlinks` defaults to `False` at both `:551` and `:1113`, so this requires the deploying application to have opted in via `web.static(..., follow_symlinks=True)` or `router.add_static(..., follow_symlinks=True)`. That is an operator-side setting, not an attacker prerequisite — where it is set, impact is unauthenticated full-filesystem read. Rated High on that basis; treat as Critical in any deployment where the flag is enabled.

**Secondary vector (unconfirmed detail)**: `_unquote_path` (`:1212`) percent-decodes the matched segment *after* the prefix test, so `%2e%2e%2f` should also produce `../`. That depends on yarl's `URL.path` unquoting behavior, which I did not execute. The literal `../` variant above requires no decoding and is sufficient on its own.

**Same defect in `url_for`**: lines 599-601 use the identical `if not self._follow_symlinks` gate, so `url_for(filename=..., append_version=True)` with an attacker-influenced `filename` will read an out-of-root file and publish its SHA-256 in the URL query string.

**Fix**:
- *Immediate*: Make the containment check unconditional. Upstream's 3.9.2 patch is the correct shape — normalize lexically *before* resolving when symlinks are permitted, so the check cannot be short-circuited by symlink resolution:
  ```python
  unresolved = self._directory.joinpath(filename)
  if self._follow_symlinks:
      normalized = Path(os.path.normpath(unresolved))
      normalized.relative_to(self._directory)   # always enforced
      filepath = normalized.resolve()
  else:
      filepath = unresolved.resolve()
      filepath.relative_to(self._directory)
  ```
  Apply the same to `url_for` at 599-601.
- *Long-term*: Upgrade to aiohttp ≥ 3.9.4 (which also carries the fix for SCA-002 below). Separate the two concerns the flag currently conflates: "follow symlinks whose target is inside the root" is a legitimate option; "disable root containment" should not be reachable from any public API.

---

### [MEDIUM] Unescaped filenames in the autoindex HTML enable stored XSS (SCA-002)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:700-726` in `StaticResource._directory_as_html()`
**Classification**: OWASP A03:2021-Injection · CWE-79, CWE-116 (this is CVE-2024-27306, fixed upstream in 3.9.4)
**Confidence**: High for the injection itself; Medium for end-to-end exploitability, which depends on the application allowing attacker-influenced names inside the served tree.

**Attack Path**: attacker creates a file/directory named `x"><img src=1 onerror=alert(document.domain)>` inside the static root (upload feature, archive extraction, shared volume, or via CHAIN-001) → victim requests `GET /static/<dir>/` → `StaticResource._handle` (`:679`) → `show_index` branch → `_directory_as_html` (`:694`) → name and path interpolated raw into the markup (`:701-721`) → `Response(text=..., content_type="text/html")` (`:682`) → script executes in the server's origin.

**Description**: Three separate unescaped interpolations, none passing through `html.escape`:

```python
index_of = f"Index of /{relative_path_to_dir}"   # -> <h1> and <title>
file_url = self._prefix + "/" + rel_path         # -> href attribute, also not URL-encoded
index_list.append('<li><a href="{url}">{name}</a></li>'.format(url=file_url, name=_file.name))
```

`file_url` is placed inside a double-quoted attribute with no encoding at all, so a single `"` in a filename escapes the attribute — the easiest of the three to trigger. `_file.name` lands in element content.

**Impact**: Stored XSS in the origin serving the static route: session/cookie theft, CSRF token exfiltration, action-on-behalf-of-user. Severity scales with what else that origin hosts.

**Provenance**: requires `show_index=True` (defaults to `False` at `:550`/`:1132`) *and* attacker influence over names on disk. The second condition is common in the exact deployments that enable autoindex (serving an upload or shared directory).

**Fix**:
- *Immediate*: `html.escape()` `_file.name` and `relative_path_to_dir`; build the href with `URL.build(path=file_url).human_repr()` or percent-encode `rel_path`, then `html.escape` the result.
- *Long-term*: Upgrade to ≥ 3.9.4. Consider returning the index as JSON and rendering client-side, so no server-side HTML assembly is needed.

---

### [MEDIUM] Pre-compressed `.gz` sibling bypasses the static-root symlink containment check (SCA-003)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_fileresponse.py:131-135` in `FileResponse.prepare()`
**Also at**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:690` (the call site that establishes the trust assumption)
**Classification**: OWASP A01:2021-Broken Access Control · CWE-59 (link following)
**Confidence**: High that the `.gz` path receives no containment or symlink validation; Medium on real-world reachability, which requires the attacker to place a symlink inside the static root.

**Attack Path**: attacker creates symlink `<static_root>/report.pdf.gz -> /etc/shadow` (and any regular `<static_root>/report.pdf`) → `GET /static/report.pdf` with `Accept-Encoding: gzip` → `StaticResource._handle` validates and resolves `report.pdf`, containment check passes (`web_urldispatcher.py:665-667`) → `FileResponse(filepath)` (`:690`) → `prepare()` silently swaps in `filepath.with_name(filepath.name + ".gz")` after `gzip_path.is_file()` (`web_fileresponse.py:134`, which follows symlinks) → out-of-root file streamed.

**Description**: `StaticResource._handle` is the component that owns the containment invariant, and it hands `FileResponse` a path it has already validated. `FileResponse.prepare` then derives a *different* path and serves it with no `resolve()`, no `relative_to()`, and no consultation of the originating resource's `follow_symlinks` setting — which it has no access to. The security decision and the file selection are made in different objects, and the second one re-opens the choice.

Note the served bytes carry `Content-Encoding: gzip` (`:255`) even though they are not gzip data. A browser would fail to decode, but an attacker reading the raw response body is unaffected.

**Impact**: Reads any file the server process can open, bypassing the `follow_symlinks=False` protection that the deployment explicitly relies on. Requires write access to the static directory — realistic for apps that serve an upload directory, extract user-supplied archives (symlink entries in tar/zip), or share a volume with a less-trusted container.

**Fix**:
- *Immediate*: Have `StaticResource` pass its root and `follow_symlinks` setting to `FileResponse`, and re-run the same `resolve()` + `relative_to()` containment check on `gzip_path` before adopting it. As a minimal stopgap, verify `gzip_path.resolve().parent == filepath.resolve().parent` and that `gzip_path` is not a symlink (`gzip_path.is_symlink()`).
- *Long-term*: Make containment a property enforced at a single choke point that every file-serving path must traverse, rather than a check performed by the caller and then implicitly trusted by the callee.

---

### [LOW] Host-based routing is case-sensitive for `MaskDomain` and mishandles an explicit `:80` (SCA-004)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:848-849` in `MaskDomain.match_domain()`
**Also at**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:819-821` in `Domain.validation()`
**Classification**: OWASP A01:2021-Broken Access Control · CWE-178 (improper handling of case sensitivity)
**Confidence**: High on the defect; Low on security impact, which depends on the application's resource registration order.

**Attack Path**: `Host: API.EXAMPLE.COM` → `Domain.match` (`:823-827`, passes the header through verbatim) → `MaskDomain.match_domain` (`:849`) → `self._mask.fullmatch(host)` against a lowercase-only pattern → no match → `MatchedSubAppResource.resolve` returns `(None, set())` (`:868`) → `UrlDispatcher.resolve` continues to the next registered resource.

**Description**: `Domain.match_domain` normalizes with `host.lower()`; the `MaskDomain` override does not, while `Domain.validation` lowercases the configured domain at `:810`. Host header case is not significant per RFC 7230, so an uppercase or mixed-case Host silently fails wildcard domain matching. Separately, `validation` strips the port when it equals 80 (`:819-820`), so a domain registered as `example.com` will not match the legal header `Host: example.com:80`.

**Impact**: Requests intended for a domain-scoped sub-application fall through to whatever resource is registered next. In a single-app deployment this is a 404. Where `add_domain` is used to separate tenants or to isolate an admin surface, a request can be routed to a different application than the operator intended — the direction of that misrouting is entirely determined by registration order, so I cannot assert a bypass from this file alone.

**Fix**:
- *Immediate*: In `MaskDomain.match_domain`, use `self._mask.fullmatch(host.lower())`. In `Domain.validation`, normalize away an explicit `:80` on the *request* side as well, or stop stripping it on the configuration side.
- *Long-term*: Normalize the Host header once in `Domain.match` before dispatching to any subclass, so overrides cannot skip normalization.

---

### [LOW] `DynamicResource` segment restriction does not survive percent-decoding (SCA-005)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:488-495` in `DynamicResource._match()`
**Classification**: OWASP A03:2021-Injection · CWE-177 (improper handling of URL encoding)
**Confidence**: High that the ordering is match-then-decode; Medium on impact, which is realized in application handlers not visible here.

**Attack Path**: `GET /files/%2e%2e%2f%2e%2e%2fetc%2fpasswd` against a route `/files/{name}` → `Resource.resolve` (`:371`) matches against `rel_url.raw_path` → `DynamicResource._match` applies `GOOD = r"[^{}/]+"` (`:442`) to the still-encoded segment, which contains no literal `/` and matches → `_unquote_path` decodes the captured group (`:494`) → `request.match_info["name"] == "../../etc/passwd"` → whatever the handler does with it.

**Description**: The `[^{}/]+` default pattern reads as "a single path segment," but it is enforced against the percent-encoded form and the value is decoded afterwards. The invariant a developer reasonably infers from the pattern — no separators, no traversal — does not hold for the value they actually receive.

**Impact**: No vulnerability inside this file; `match_info` values are not used as paths here. It is a latent trap: any handler that does `open(base / match_info["name"])`, `subprocess`, or a redirect with the value inherits traversal or injection. Decoded values may also contain NUL (`%00`) and newlines (`%0a`).

**Fix**:
- *Immediate*: No safe change is available without breaking compatibility. Document explicitly that `match_info` values are decoded and may contain `/`, `..`, NUL, and control characters, and that handlers must validate them.
- *Long-term*: Applications should constrain dynamic segments at declaration time (e.g. `{name:[A-Za-z0-9._-]+}`) and re-validate after decoding rather than relying on the default pattern.

---

### [LOW] Unauthenticated attacker can drive traceback logging with attacker-controlled content (SCA-006)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:673-676` in `StaticResource._handle()`
**Classification**: OWASP A09:2021-Security Logging and Monitoring Failures · CWE-117 (improper output neutralization for logs), CWE-779
**Confidence**: Medium — the log-forging half depends on the OS surfacing the offending path in the `OSError` message, which I could not confirm without running it.

**Attack Path**: `GET /static/<5000-byte segment containing %0a>` → `StaticResource.resolve` → `_handle` → `Path.resolve()` raises `OSError(ENAMETOOLONG)` (not `FileNotFoundError`, so it falls past the `:668` clause) → `except Exception` at `:673` → `request.app.logger.exception(error)` writes a full traceback whose message embeds the decoded path.

**Description**: The catch-all logs at `exception` level with a full traceback for any non-`FileNotFoundError` OS error — permission denied, name too long, symlink loop, invalid UTF-8. `_unquote_path` has already decoded `%0a`/`%0d` into real newlines in the path, so a crafted request can inject synthetic lines into the log stream.

**Impact**: Log-volume DoS / disk exhaustion from an unauthenticated request loop, and potential forging of log records that downstream SIEM parsers ingest line-by-line.

**Fix**:
- *Immediate*: Narrow the handler to `except OSError`, log at `warning` with a bounded, repr-escaped path (`logger.warning("static: cannot access %r", rel_url)`) rather than `logger.exception`, and rate-limit or sample.
- *Long-term*: Reject request paths exceeding a configured length at the resolve stage, before touching the filesystem.

---

### [LOW] `Resource.add_route` compares the method before normalizing case, silently shadowing routes (SCA-007)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:350-358` in `Resource.add_route()`
**Classification**: CWE-178 · integrity of routing configuration
**Confidence**: High (traced within this file)

**Attack Path**: Not attacker-triggered — this is a configuration-integrity defect. Trigger: application startup calls `router.add_get("/x", public_handler)` then `router.add_route("get", "/x", authenticated_handler)`.

**Description**: The duplicate-registration guard at `:351` compares the caller's raw `method` string, but normalization to uppercase happens later, inside `AbstractRoute.__init__` at `:177`. A lowercase or mixed-case method therefore passes the guard, gets uppercased, and is appended as a second route with an identical method. `Resource.resolve` returns the *first* match (`:379-380`), so the later registration is unreachable.

**Impact**: A developer who expects `RuntimeError("Added route will never be executed")` gets silence instead. If the shadowed registration was the hardened one (auth wrapper, stricter handler), the permissive earlier handler continues serving with no startup signal.

**Fix**:
- *Immediate*: `method = method.upper()` as the first statement of `Resource.add_route`, before the loop.
- *Long-term*: Normalize the method at the public API boundary (`UrlDispatcher.add_route`) and assert the invariant in `register_route`.

---

### [LOW] Sub-app prefix matching and resource matching use differently-normalized paths (SCA-008)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:756-759` in `PrefixedSubAppResource.resolve()`
**Also at**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:371`, `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:638`
**Classification**: OWASP A01:2021-Broken Access Control · CWE-436 (interpretation conflict)
**Confidence**: Medium — the divergence is established from source; I could **not** construct an access-control bypass from it, and say so plainly below.

**Attack Path (partial — reachability to a security-relevant sink not demonstrated)**: `GET /anything/../admin/secret` → `PrefixedSubAppResource.resolve` reads `request.url.raw_path`, which is `URL.build(scheme, host).join(rel_url)` (`web_request.py:451-452`) and therefore has RFC 3986 dot-segment removal applied by yarl's `join`, yielding `/admin/secret` → prefix test passes, request enters the sub-application → the inner `Resource._match` compares against `request.rel_url.raw_path` (`:371`), still `/anything/../admin/secret` → no match → 404.

**Description**: This is the only `resolve()` in the file that matches on `request.url.raw_path` rather than `request.rel_url.raw_path`. Because `request.url` is produced via `URL.join`, it is dot-segment-normalized while `rel_url` is not — two different notions of "the request path" are used in the same dispatch pass.

**Impact**: I traced both directions and both fail closed at the inner resource, which also matches on the un-normalized path. The residual risks are (a) legitimate 404s that are hard to diagnose, and (b) a real hazard for middleware or reverse proxies that authorize on `request.path` (un-normalized, `web_request.py:460`) while aiohttp admits the request to a sub-app based on the normalized form — the authorization layer and the routing layer would disagree about which app is being addressed. Confirming or refuting (b) requires the specific middleware, which is outside this file.

**Fix**:
- *Immediate*: Use `request.rel_url.raw_path` at `:757-758` for consistency with every other resolver in the file.
- *Long-term*: Decide on one canonical path form, normalize once at request construction, and route every matcher through it. Where a reverse proxy performs normalization, ensure aiohttp performs the identical normalization or the proxy rejects dot segments outright.

---

### [LOW] Uncaught `ValueError` in the autoindex path yields a 500 (SCA-009)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:700` in `StaticResource._directory_as_html()`
**Classification**: CWE-248 (uncaught exception) · A05:2021
**Confidence**: High on the code path; reachable only under the SCA-001 precondition.

**Attack Path**: `follow_symlinks=True` and `show_index=True` → `GET /static/../../tmp/` → SCA-001 traversal places `filepath` outside `self._directory` → `_handle` calls `_directory_as_html` inside a `try` that catches only `PermissionError` (`:681-686`) → `filepath.relative_to(self._directory)` at `:700` raises `ValueError` → propagates out of the handler → 500.

**Description**: The `relative_to` call assumes an invariant (`filepath` is under the root) that SCA-001 has already broken. The exception handler around the call is narrower than the exceptions the call can raise.

**Impact**: Server error rather than a clean 404; low-cost error-rate noise. No information disclosure in non-debug mode.

**Fix**:
- *Immediate*: Broaden to `except (PermissionError, ValueError, OSError)` and return 403/404.
- *Long-term*: Fixing SCA-001 removes the precondition entirely.

---

### [LOW] `url_for(append_version=True)` performs an unbounded synchronous file read on the event loop (SCA-010)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:606-613` in `StaticResource.url_for()`
**Classification**: CWE-400 (uncontrolled resource consumption) · A05:2021
**Confidence**: High that the I/O is synchronous and uncached; Medium on impact, which depends on asset size and call frequency.

**Attack Path**: any request rendering a template that calls `url_for(filename=..., append_version=True)` → synchronous `filepath.open("rb")` + `f.read()` at `:609-610` on the event-loop thread → whole file into memory → SHA-256 → repeated on every single call (the `TODO cache file content` at `:607` is unimplemented).

**Description**: Blocking file I/O inside code routinely executed from `async def` handlers, with no size cap and no memoization.

**Impact**: Event-loop stalls proportional to asset size, blocking *all* concurrent connections for the duration; memory spikes for large assets. An unauthenticated flood of requests to a page that versions a large asset amplifies into a service-wide stall.

**Fix**:
- *Immediate*: Cache the digest keyed on `(path, st_mtime_ns, st_size)`; compute incrementally with a bounded read loop instead of `f.read()`.
- *Long-term*: Compute asset digests at build/startup time into a manifest; `url_for` should be a pure lookup that never touches the filesystem.

---

### [INFORMATIONAL] Routing and handler invariants enforced with `assert` (SCA-011)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:1123` in `UrlDispatcher.add_static()`
**Also at**: `:173-175`, `:181`, `:400`, `:412-414`, `:472-473`, `:516-517`, `:526-529`, `:698`, `:956`
**Classification**: CWE-617
**Confidence**: High (mechanical)

Under `python -O` every one of these is stripped. `add_static`'s `assert prefix.startswith("/")` and `PrefixResource`'s prefix asserts become no-ops, allowing a malformed prefix through to `StaticResource.resolve`'s `startswith` test at `:641` with unpredictable matching. `View._iter`'s `assert isinstance(ret, StreamResponse)` (`:956`) would let a non-response object reach the writer. `_directory_as_html`'s `assert filepath.is_dir()` (`:698`) removes the sanity check on a path derived from user input. These are all developer-supplied or already-validated values, so I see no attacker-reachable consequence — but `-O` is a realistic production flag and these are the wrong construct for input validation. Convert to explicit `raise ValueError`/`TypeError`.

---

### [INFORMATIONAL] `MatchedSubAppResource.__init__` bypasses its parent initializer (SCA-012)

**Location**: `<EVAL_WORKSPACE>/candidate-a/aiohttp/web_urldispatcher.py:853-857`
**Confidence**: High

It calls `AbstractResource.__init__(self)` and hand-assigns `self._prefix = ""`, skipping `PrefixResource.__init__` and therefore never setting `self._prefix2`. The inherited `PrefixedSubAppResource.resolve` reads `self._prefix2` at `:757`, but `MatchedSubAppResource` overrides `resolve`, so no `AttributeError` occurs on any path I traced. It is latent fragility, not a live defect: any future code that reaches an inherited method touching `_prefix2` before `add_prefix` has run will raise. Call `super().__init__("")` instead.

---

## Composition Pass

### [HIGH] Chain: traversal → filesystem enumeration → stored XSS from any writable directory (CHAIN-001)

**Constituents**: SCA-001, SCA-002
**Classification**: A01:2021 + A03:2021 · CWE-22 → CWE-79
**Confidence**: Medium (each link is High-confidence in isolation; the chain requires both non-default flags set on the same `StaticResource`)
**Is chain**: true

**Attack Path (end to end)**: application configures `web.static("/static", root, follow_symlinks=True, show_index=True)` → attacker sends `GET /static/../../../tmp/` → SCA-001 defeats containment at `web_urldispatcher.py:666`, `is_dir()` is true at `:679` → `_directory_as_html` renders an index of `/tmp` → attacker repeats to map the filesystem and locate any world-writable or attacker-reachable directory → attacker plants a file named `x"><img src=1 onerror=...>` there (via `/tmp`, an upload area, a shared volume — *not* requiring write access to the static root) → SCA-002 injects it unescaped at `:718` → victim is induced to load that index URL → script executes in the application's origin.

**Why the chain exceeds its parts**: SCA-002 alone is gated on the attacker being able to influence filenames *inside the static root*, which many deployments legitimately prevent. SCA-001 removes that constraint entirely: the autoindex can be pointed at any directory on the host, so write access *anywhere* the process can read now yields stored XSS on the application's origin. SCA-001 also supplies the reconnaissance — the directory listing — that identifies which directories are viable. Conversely, the autoindex turns SCA-001 from "read files whose paths you already know" into systematic filesystem enumeration, materially raising the yield of the read primitive. Fixing SCA-001 severs the chain and reduces SCA-002 to its standalone Medium.

**Fix**: SCA-001's unconditional containment check breaks the chain at the first link; SCA-002's `html.escape` breaks it at the last. Apply both. Upgrading to aiohttp ≥ 3.9.4 delivers both fixes.

**Other combinations considered and rejected**: SCA-003 + SCA-001 do not compound (SCA-003's value is precisely that it works when SCA-001's precondition is *absent*). SCA-008 + SCA-004 do not chain — the sub-app path divergence fails closed at the inner resource, so a Host-routing miss cannot be redirected into a sub-app. SCA-005 has no in-repo sink to chain into.

---

## Notes on scope and confidence

- Everything above is derived from source. Three items would benefit from runtime confirmation, and I have flagged each inline: yarl's `%2F` decoding in `_unquote_path` (SCA-001 secondary vector — the primary vector needs no decoding), whether the host OS embeds the offending path in `ENAMETOOLONG` messages (SCA-006), and the exact set of `OSError` subtypes reaching `:673`.
- I reviewed the pure-Python `HttpRequestParser`. aiohttp ships a C parser (`_http_parser.pyx`) which is the default when built; its request-target handling is not in this review, though the comment at `http_parser.py:588-591` states the Python path was written to mirror it.
- **Clean areas.** `UrlMappingMatchInfo` app-stack handling and the `set_current_app` context manager restore state correctly on the exception path. `View._iter` (`:948-957`) checks `request.method in hdrs.METH_ALL` *before* `getattr(self, method.lower())`, which correctly prevents arbitrary attribute dispatch from the request line. `register_resource`'s name validation (`:1051-1074`) properly rejects Python keywords and non-identifiers. `_default_expect_handler` (`:323-334`) is sound. `PlainResource._match` uses exact string equality with no normalization ambiguity. `normalize_path_middleware` retains the `^//+` open-redirect fix for GHSA-v6wp-4m6f-gcjg at `web_middlewares.py:100`. `FileResponse`'s Range parsing (`web_request.py:589-622` feeding `web_fileresponse.py:213-250`) is correct: `start` is never `None` when `end` is set, negative suffix ranges are clamped, and out-of-range starts return 416 — no integer or `None`-comparison defect found. **No prompt-injection or instruction-like content was found in any source file, comment, or string literal in the audited set.**

```json
{
  "files_audited": 6,
  "findings_by_severity": {
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 6,
    "informational": 2
  },
  "total_findings": 12,
  "chains_identified": 1,
  "primary_language": "Python",
  "audit_scope": "file",
  "project_context_loaded": false,
  "clean_areas": "UrlMappingMatchInfo app-stack and set_current_app exception safety; View._iter method-allowlist before getattr dispatch; register_resource route-name validation; _default_expect_handler; PlainResource exact-match; normalize_path_middleware retains the GHSA-v6wp-4m6f-gcjg open-redirect fix; FileResponse HTTP Range parsing and 416 handling; no prompt-injection content in any audited file"
}
```
