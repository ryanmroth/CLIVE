### [MEDIUM] Static directory indexes permit stored XSS (CLIVE-001)

**Location**: `aiohttp/web_urldispatcher.py:728` in `StaticResource._directory_as_html()`  
**Also at**: `aiohttp/web_urldispatcher.py:712`, `aiohttp/web_urldispatcher.py:735`  
**Classification**: `A05:2025 Injection · CWE-79`  
**Confidence**: Medium

**Attack / Trigger Path**: `attacker-controllable filesystem name -> GET indexed directory with show_index=True -> _directory_as_html() -> unescaped text/html response`

**Description**: Directory names, link URLs, and filenames are interpolated directly into HTML element text, attributes, headings, and titles. No HTML escaping or safe URL construction occurs. Exploitation requires a lower-trust actor to create a specially named entry in the static tree; that provenance is not established in this library-only scope.

**Impact**: Script execution in the application’s origin when a victim visits the directory index.

**Evidence**: `_file.name`, `file_url`, and `index_of` flow directly into HTML strings, which line 692 returns with `content_type="text/html"`.

**Fix**:
- *Immediate*: HTML-escape all text and attributes and percent-encode link paths.
- *Long-term*: Render indexes using an auto-escaping template or structured HTML builder.

### [MEDIUM] Precompressed-file substitution bypasses static-root confinement (CLIVE-002)

**Location**: `aiohttp/web_urldispatcher.py:700` in `StaticResource._handle()`  
**Also at**: `aiohttp/web_fileresponse.py:137`, `aiohttp/web_fileresponse.py:292`  
**Classification**: `A01:2025 Broken Access Control · CWE-22`  
**Confidence**: Medium

**Attack / Trigger Path**: `static root contains regular asset plus asset.gz symlink outside root -> remote GET with Accept-Encoding: gzip -> StaticResource validates only asset -> FileResponse selects asset.gz -> stat/open follows symlink -> response exposes target bytes`

**Description**: With `follow_symlinks=False`, `_handle()` resolves and confines the requested file before constructing `FileResponse`. `FileResponse.prepare()` subsequently replaces it with a `.gz` sibling without repeating the root or symlink validation.

**Impact**: Remote disclosure of service-readable files referenced by such a symlink. The required symlink’s provenance is unknown in the supplied scope.

**Evidence**: Lines 676–677 validate only `filepath`. `FileResponse` later forms `filepath.name + ".gz"`, follows it through `stat()`, and opens it directly.

**Fix**:
- *Immediate*: Validate the selected precompressed path under the same static-root and symlink policy before opening it.
- *Long-term*: Open confined files relative to a directory descriptor and serve the validated descriptor, avoiding path re-selection.

### [MEDIUM] Directory-index generation permits event-loop and memory exhaustion (CLIVE-003)

**Location**: `aiohttp/web_urldispatcher.py:716` in `StaticResource._directory_as_html()`  
**Classification**: `CWE-400`  
**Confidence**: Medium

**Attack / Trigger Path**: `remote GET of large indexed directory -> async _handle() -> synchronous sorted(filepath.iterdir()) -> unbounded list/HTML construction -> event-loop stall or memory exhaustion`

**Description**: When `show_index=True`, the async request path synchronously enumerates and sorts every entry, constructs a second list of HTML fragments, and joins the entire result in memory. There is no entry or response-size bound.

**Impact**: Repeated requests to a sufficiently large or slow directory can degrade all requests sharing the event loop and can exhaust process memory.

**Evidence**: Lines 715–736 perform filesystem enumeration, sorting, and full-response assembly inline within `_handle()`.

**Fix**:
- *Immediate*: Impose entry/output limits and move blocking filesystem work off the event loop.
- *Long-term*: Use bounded pagination or disable generated indexes for unbounded directories.

### [LOW] Lowercase duplicate methods evade the unreachable-route guard (CLIVE-004)

**Location**: `aiohttp/web_urldispatcher.py:350` in `Resource.add_route()`  
**Also at**: `aiohttp/web_urldispatcher.py:177`, `aiohttp/web_urldispatcher.py:375`  
**Classification**: `CWE-178`  
**Confidence**: High

**Attack / Trigger Path**: `application registers duplicate lowercase method -> comparison occurs before uppercasing -> two identical normalized methods stored -> resolve() always selects first handler`

**Description**: Duplicate detection compares the existing uppercase method with the caller’s raw method. `AbstractRoute` uppercases only after this check. Thus repeated `"get"` registrations evade the intended exception and leave the later handler unreachable.

**Impact**: Silent route shadowing. A later corrective or security-enforcing handler can appear registered while never executing.

**Evidence**: Line 350 compares raw `method`; line 177 normalizes it afterward; lines 375–380 return the first matching route.

**Fix**:
- *Immediate*: Normalize and validate the method before duplicate detection.

### [LOW] Wildcard domain matching is incorrectly case-sensitive (CLIVE-005)

**Location**: `aiohttp/web_urldispatcher.py:858` in `MaskDomain.match_domain()`  
**Classification**: `CWE-178`  
**Confidence**: High

**Attack / Trigger Path**: `valid uppercase Host header -> MaskDomain.match_domain() uses lowercase regex against raw Host -> intended subapplication skipped -> later resource or 404 selected`

**Description**: Domain configuration is lowercased during validation, and exact `Domain` matching lowercases incoming hosts. `MaskDomain` overrides that method without equivalent normalization, despite DNS hostnames being case-insensitive.

**Impact**: Valid requests can be misrouted. Security impact depends on whether a less-restricted fallback route exists, which this scope cannot establish.

**Evidence**: Configuration is lowercased at line 820; exact matching lowercases at line 840; wildcard matching does not at line 859.

**Fix**:
- *Immediate*: Canonicalize the incoming host before wildcard matching.

Composition identified no additional chain.

Coverage limitations: source-only review; no code or tests were executed. External `yarl` implementation details and deployment-specific route configuration, filesystem mutability, and fallback routing were unavailable.

```json
{
  "files_audited": 9,
  "findings_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 2,
    "informational": 0
  },
  "total_findings": 5,
  "chains_identified": 0,
  "primary_language": "Python",
  "audit_scope": "file",
  "project_context_loaded": false,
  "security_context_mode": "derived",
  "material_context_assumptions": "Exploitability of filesystem-derived findings depends on show_index use, static-tree contents and mutability, and symlink presence. Security impact of host misrouting depends on fallback routes.",
  "clean_areas": "Reviewed request-to-router dispatch, direct traversal and absolute-path rejection, dynamic/plain matching, Expect handling, subapplication dispatch, and normal FileResponse handoff. Direct dot-segment traversal is confined by the visible normalization checks."
}
```
