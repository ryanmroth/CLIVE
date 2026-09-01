### [HIGH] `follow_symlinks=True` permits request-path traversal outside the static root (CLIVE-001)

**Location**: `aiohttp/web_urldispatcher.py:665` in `StaticResource._handle()`  
**Also at**: `aiohttp/web_urldispatcher.py:647`, `aiohttp/web_fileresponse.py:276`  
**Classification**: `A01:2025 Broken Access Control · CWE-22`  
**Confidence**: High

**Attack / Trigger Path**: `remote request for /<static-prefix>/%2e%2e/<target> -> HTTP parser preserves the encoded raw path -> StaticResource.resolve() decodes the suffix into filename -> StaticResource._handle() joins and resolves it -> follow_symlinks=True skips the only root-containment check -> FileResponse.prepare() opens and sends the resolved external file`

**Description**: Static routing derives `filename` from the externally supplied request path. `_handle()` rejects absolute paths, but a relative path containing `..` has no anchor. After joining it to the configured directory and resolving it, containment is checked only when `_follow_symlinks` is false. Enabling `follow_symlinks` therefore permits ordinary parent-directory traversal; the option disables both symlink-target confinement and lexical path confinement.

The pure-Python parser constructs the request URL with `encoded=True` at `aiohttp/http_parser.py:592`, and `StaticResource.resolve()` obtains the filename by passing the raw suffix through `_unquote_path()`. The corresponding Cython parser does the same at `aiohttp/_http_parser.pyx:624`. This supports encoded traversal segments reaching the filesystem path calculation without losing the static prefix during initial routing.

**Impact**: An unauthenticated client can read files accessible to the server process outside the configured static directory when the static route is reachable and `follow_symlinks=True`.

**Evidence**: `StaticResource.resolve()` reads `request.rel_url.raw_path` and stores its decoded suffix as `match_info["filename"]` at lines 637-648. `_handle()` joins that value to `_directory`, calls `resolve()`, and executes `filepath.relative_to(self._directory)` only under `if not self._follow_symlinks` at lines 656-668. A resolved file is handed to `FileResponse` at line 690, whose `prepare()` opens the path at `aiohttp/web_fileresponse.py:276`.

**Fix**:
- *Immediate*: When symlink following is enabled, independently normalize and verify that the request’s lexical path remains beneath the static root before resolving symlinks.
- *Long-term*: Centralize static-path resolution so lexical traversal prevention and the selected symlink policy are separate, explicit controls applied to every file candidate.

### [MEDIUM] Directory indexes render filesystem names as unescaped HTML (CLIVE-002)

**Location**: `aiohttp/web_urldispatcher.py:718` in `StaticResource._directory_as_html()`  
**Also at**: `aiohttp/web_urldispatcher.py:701`, `aiohttp/web_urldispatcher.py:725`, `aiohttp/web_response.py:619`  
**Classification**: `A05:2025 Injection · CWE-79`  
**Confidence**: Medium

**Attack / Trigger Path**: `principal able to create or rename an entry in an indexed static tree -> entry name contains HTML markup/attribute delimiters -> victim requests that directory with show_index=True -> _directory_as_html() interpolates the name and URL verbatim -> Response emits it as text/html -> victim browser interprets attacker markup`

**Description**: The directory-index generator directly interpolates directory names, entry names, relative URLs, and the page title into HTML. It applies neither HTML text escaping nor attribute escaping/URL quoting. `Response(text=..., content_type="text/html")` encodes the supplied string verbatim; it does not sanitize it.

Exploitability depends on filesystem provenance not present in this package snapshot. It is exploitable where a lower-trust principal can control names within the served directory, such as a static tree shared with an upload or content-publishing workflow. If only trusted administrators can create entries, this remains a latent rendering defect rather than a remote attack path. `show_index` defaults to false.

**Impact**: A malicious filesystem name can execute script in the static origin when another user browses the generated index, enabling same-origin actions or data access available to that user.

**Evidence**: `_file.name` is inserted directly as anchor body and `file_url` directly as a quoted `href` at lines 707-721. The current directory name is inserted into `<h1>` and `<title>` at lines 700-725. `_handle()` returns that string with `content_type="text/html"` at lines 679-684, and `Response` merely encodes `text` at `aiohttp/web_response.py:602-620`.

**Fix**:
- *Immediate*: HTML-escape all text-node values and attribute values, and URL-quote each path component used in `href`.
- *Long-term*: Generate indexes through a context-aware HTML renderer and add hostile-filename coverage for every supported filesystem.

### [MEDIUM] Precompressed-file selection bypasses the static route’s no-symlink confinement (CLIVE-003)

**Location**: `aiohttp/web_fileresponse.py:134` in `FileResponse.prepare()`  
**Also at**: `aiohttp/web_urldispatcher.py:665`, `aiohttp/web_urldispatcher.py:690`, `aiohttp/web_fileresponse.py:276`  
**Classification**: `A01:2025 Broken Access Control · CWE-59`  
**Confidence**: Medium

**Attack / Trigger Path**: `lower-trust principal creates ordinary <name> plus <name>.gz symlink inside the served root -> remote request for <name> with Accept-Encoding containing gzip -> StaticResource validates only <name> under follow_symlinks=False -> FileResponse.prepare() substitutes unchecked <name>.gz -> is_file(), stat(), and open() follow its symlink -> external target bytes are returned`

**Description**: `StaticResource._handle()` resolves and confines the requested path before constructing `FileResponse`. `FileResponse.prepare()` subsequently derives a different `.gz` pathname and selects it when `is_file()` succeeds. That alternate pathname is never resolved against or checked beneath the static root, and normal `Path.is_file()`, `stat()`, and `open()` operations follow symlinks. Consequently, the file actually opened can bypass the `follow_symlinks=False` control.

The repository does not establish whether an untrusted principal can create symlinks in a deployed static root. The finding is directly exploitable by a local/constrained principal with that ability; ordinary upload APIs that cannot create symlinks do not satisfy the precondition.

**Impact**: A principal able to create a symlink but unable to read its target can disclose files readable by the aiohttp process. This violates the default static-root confinement policy.

**Evidence**: `_handle()` validates `filepath` at lines 665-668 and passes it to `FileResponse` at line 690. `prepare()` constructs `filepath.with_name(filepath.name + ".gz")`, follows it through `is_file()`, replaces the validated path at lines 130-136, and later opens that new path at line 276.

**Fix**:
- *Immediate*: Resolve and apply the static-root/symlink policy to the exact compressed candidate before selecting it.
- *Long-term*: Pass an opened, validated file descriptor or an explicit confinement policy into file response handling so post-validation path substitution cannot bypass routing controls.

### [LOW] Wildcard domain routing is incorrectly case-sensitive (CLIVE-004)

**Location**: `aiohttp/web_urldispatcher.py:848` in `MaskDomain.match_domain()`  
**Also at**: `aiohttp/web_urldispatcher.py:823`, `aiohttp/web_urldispatcher.py:866`, `aiohttp/web_app.py:362`  
**Classification**: `CWE-178`  
**Confidence**: High

**Attack / Trigger Path**: `request with an uppercase character in a Host value covered by a configured wildcard -> Application.add_domain() selected MaskDomain -> MatchedSubAppResource.resolve() calls MaskDomain.match() -> case-sensitive regex fullmatch fails -> dispatcher skips the intended subapplication and selects a later resource or returns 404`

**Description**: Domain configuration is lowercased during `Domain.validation()`. Exact-domain matching lowercases the request Host before comparing it, but the `MaskDomain` override applies its lowercase regex directly to the original Host value. DNS hostnames are case-insensitive, so a case-only variation changes route selection for wildcard domains.

A 404 is the source-established consequence. A security-boundary bypass would require deployment evidence that a later fallback route has weaker controls; that is not established here.

**Impact**: Valid requests can be routed away from the intended virtual-host subapplication. Deployments relying on wildcard host routing for isolation may experience policy inconsistency if fallback routes differ.

**Evidence**: `Domain.validation()` lowercases configured domains at line 810 and `Domain.match_domain()` lowercases the request value at line 830. `MaskDomain.match_domain()` overrides that behavior with `self._mask.fullmatch(host)` at lines 848-849 without normalizing `host`. `UrlDispatcher.resolve()` continues to subsequent resources after a non-match.

**Fix**:
- *Immediate*: Normalize the request host to lowercase before applying the wildcard regex.
- *Long-term*: Parse and canonicalize configured domains and request authorities through one shared routine before any exact or wildcard comparison.

### [LOW] Lowercase route registration bypasses duplicate-method rejection (CLIVE-005)

**Location**: `aiohttp/web_urldispatcher.py:350` in `Resource.add_route()`  
**Also at**: `aiohttp/web_urldispatcher.py:177`, `aiohttp/web_urldispatcher.py:375`  
**Classification**: `CWE-178`  
**Confidence**: High

**Attack / Trigger Path**: `resource already contains GET handler -> application registers "get" on the same resource -> duplicate check compares existing "GET" with raw "get" and permits it -> AbstractRoute uppercases the new method to "GET" -> Resource.resolve() returns the first GET route -> newly registered handler is unreachable`

**Description**: `Resource.add_route()` performs its duplicate check before method canonicalization. `AbstractRoute.__init__()` uppercases the method only after the check. This allows two routes with the identical stored method on one resource even though the method explicitly normalizes lowercase input and the duplicate guard says the later route would never execute.

**Impact**: Route-table integrity is violated: application startup succeeds, but the newly registered handler is silently unreachable. This can leave an older handler active when the application expected a replacement or newly secured handler.

**Evidence**: The duplicate comparison uses the caller-provided `method` at lines 350-356. `ResourceRoute` then delegates to `AbstractRoute`, which uppercases it at line 177. Resolution iterates in insertion order and returns the first matching route at lines 375-380.

**Fix**:
- *Immediate*: Uppercase and validate the method before duplicate detection in `Resource.add_route()`.
- *Long-term*: Use one canonical method representation at all route-registration boundaries and assert route-table uniqueness after registration.

### Coverage limitations

The supplied workspace contains the aiohttp package source but no application/deployment configuration, so actual use of `follow_symlinks`, `show_index`, wildcard domains, and lower-trust write access to static roots could not be established. Runtime behavior was not executed. Relevant request parsing, request construction, application dispatch, route-definition registration, response encoding, file-response preparation, and HTTP response finalization paths were inspected statically. The composition pass identified no additional chain that materially increases the severity of the consolidated findings.

```json
{
  "files_audited": 11,
  "findings_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 2,
    "informational": 0
  },
  "total_findings": 5,
  "chains_identified": 0,
  "primary_language": "Python",
  "audit_scope": "file",
  "project_context_loaded": false,
  "security_context_mode": "derived",
  "material_context_assumptions": "The package is an HTTP server framework and the audited router is reachable through Application request dispatch. Deployment-specific enablement of optional static and wildcard-domain features, static-root write provenance, and fallback-route policy are unknown; findings state those conditions explicitly.",
  "clean_areas": "Reviewed plain and dynamic resource matching, route resolution and 404/405 selection, Expect handling, prefixed and matched subapplication dispatch, class-based view dispatch, URL generation helpers, static absolute-path rejection, named-resource registration, and route/resource view wrappers; no additional justified finding was identified."
}
```
