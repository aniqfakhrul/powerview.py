# PowerView frontend

Server-rendered Flask/Jinja pages with local CSS and native JavaScript modules.
No production Node build, CDN, external font, or frontend framework is required.

## Structure

```text
web/frontend.py                 App creation, page registry, shared render context, asset URLs
front-end/
  templates/
    base.html                   Document and shared asset loading
    layouts/workspace.html      Application shell
    partials/                   Navigation and header
    components/                 Explicit-argument Jinja macros
    pages/explorer.html         Explorer markup and page assets
    pages/placeholder.html      Starting point for new modules
  static/
    css/                        Tokens, reset, shared layout/components
      pages/explorer.css        Two-pane Explorer and responsive rules
    js/
      app.js                    Shared module entry point
      core/api.js               Same-session JSON transport and strict mutation results
      core/directory.js         Endpoint contracts and object attribute helpers
      core/dn.js                Escaped-DN parsing and naming-context resolution
      pages/explorer.js         Explorer orchestration
      pages/explorer/           Tree, details, dialogs, focus, DOM, request state
    images/                     Local mark and stroke icon sprite
  tests/                        Node unit tests and browser contract tests
```

## Explorer behavior

The Explorer is a classic two-pane directory browser: **a fully expandable object
tree on the left and the selected object's property grid on the right**. There is
no results table. It uses the CLI's existing authenticated session through the API;
the frontend never receives connection credentials.

- Naming contexts come from server info, with the connected domain as fallback.
  Domain roots are labelled with their DNS name.
- Expanding a branch requests its direct children with only `name` and
  `objectClass`. Clicking an object selects and expands it; the chevron toggles.
  A confirmed leaf loses its chevron. Branches render 500 children at a time.
- The tree pane is resizable (drag, arrow keys, double-click to reset); the width
  is remembered per browser. Labels never truncate; the pane scrolls horizontally.
- The toolbar address bar shows the selected DN and navigates to any DN typed
  into it. Typing two or more characters of a name suggests matching objects in
  the default domain naming context; choosing one navigates to it. Objects in
  other naming contexts are reached by DN. The first Escape closes suggestions
  and the second restores the selected DN. DN-valued attributes are links that
  reveal the target in the tree.
- Selecting an object loads its attributes with a BASE query. Request
  cancellation prevents stale responses from replacing a newer selection.
- Attributes are edited inline, one input per value. Save replaces the values and
  Clear attribute removes them. Failed writes retain the draft; save or cancel it
  before navigating elsewhere.
- New supports user, group, and OU in the selected container (or a leaf's parent).
  Move requires an existing destination in the same naming context. Delete asks
  for confirmation. Naming-context roots cannot be moved or deleted.
- Mutations are never automatically retried, and only JSON `true` confirms success.
- Known binary/system fields offer no edit control. The API's binary
  serialization is lossy; this is not a binary attribute editor. Single values
  beginning with `@` are rejected because PowerView interprets them as server-side
  files. Creation names containing DN delimiters are rejected because the creation
  endpoints concatenate names into DNs without escaping.
- Light/dark themes follow the OS. On phones, the directory opens as a
  focus-contained overlay. Tree keys: arrows, Home/End, Enter.

## Motion and loading

Shared `static/css/motion.css` adds short panel, Fields-menu and tab entrances.
`--duration-fast` (120ms) and `--duration-enter` (160ms) use the existing
`--ease-out` curve. Icon buttons and panel tabs transition their colors in 120ms.
The shared active-tab underline translates and scales in 160ms using `--ease-out`;
initial placement, resizing and reduced motion align it immediately.
`components/object-panel/tab-indicator.js` tracks tab widths, including font and
count changes, with a resize observer.

`components/loading.js` marks a region busy immediately and delays placeholders
by 200ms. Completion or abort clears its timer and busy state. Shared tables
show eight skeleton rows; dashboard evidence shows six. Other dashboard sections
show content-shaped skeletons while their source is pending and switch to
error or empty text as soon as it resolves; the header status keeps text progress. Delayed skeletons breathe
over 1400ms without shimmer. Reduced motion disables these animations and the
Explorer tree's busy pulse. Loading, empty and error states remain distinct.

## Status bar and connection

Every page shares the bottom status bar (`partials/statusbar.html`). Page modules
write messages to `#status-message`. `js/app.js` starts
`components/connection-status.js`, which reads `/api/connectioninfo` and shows the
protocol, `user@domain`, LDAP address, and a live dot; the name server and last
check time are in the tooltip. `connectioninfo` performs a real liveness check, so
it runs on load, when the tab becomes visible or focused, every 60 seconds while
visible, and when any API request fails (`powerview:request-failed`, dispatched by
`core/api.js`). Checks are at least 5 seconds apart. State changes are announced
to screen readers; routine refreshes are not.

## Backend boundary

`APIServer` owns authentication and API routes. `register_frontend` uses its
existing authentication wrapper. Static assets are public and contain no session
secrets. `asset_url` resolves deployment prefixes and adds a release cache key.
Paths resolve relative to the Python package, independent of the launch directory.
The existing `MANIFEST.in` includes templates and assets in distributions.

New modules start from `pages/placeholder.html`. Add a `Page` entry in `web/frontend.py`, extend
`layouts/workspace.html`, and load page-specific files in `styles`/`scripts` blocks.
Use `url_for` for navigation and `asset_url` for static assets. Keep reusable UI
in macros and focused modules; directory data enters the DOM through textContent.

Sidebar icons come from each `Page` entry. On desktop with a fine pointer, the
sidebar collapses to a 48px icon rail and expands over the workspace on hover or
keyboard focus without shifting page content. Touch-only desktop layouts keep
the full sidebar, and mobile uses horizontal navigation. Expansion respects
reduced-motion preferences. `tests/sidebar.browser.cjs` covers these behaviors.

The sidebar footer provides System, Light and Dark themes; mobile places the
control beside the brand. System is the default and follows OS changes. Explicit
choices persist in `localStorage` and sync across tabs. `theme.js` applies the
stored choice before styles load; unavailable storage still permits switching
for the current page. Color tokens use `light-dark()` with the root color scheme.
`tests/theme.browser.cjs` covers theme selection and persistence.

## Verification

Python integration tests (all page routes, assets, URL prefixes, Basic Auth, and
escaped/multi-valued RDN moves):

```sh
.venv/bin/python -m unittest tests.test_explorer_backend
```

Dependency-free JavaScript unit tests (Node 20+):

```sh
node --test powerview/web/front-end/tests/explorer.test.mjs
```

Browser tests require Playwright and an installed Chrome. Start a local shell
preview with normal project dependencies:

```python
from powerview.web.frontend import create_web_app, register_frontend

app = create_web_app(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
register_frontend(app.add_url_rule)
app.run(host='127.0.0.1', port=5011)
```

Then run:

```sh
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/explorer.browser.cjs
```

Set `PLAYWRIGHT_MODULE` to an installed Playwright module path if it is outside
Node's lookup path. Tests intercept **all** API requests with explicit fixtures;
no test writes to Active Directory. Coverage includes large branches, filtering,
text-safe rendering, draft preservation, CRUD payloads, confirmations, error
recovery, and mobile focus containment. Live verification should remain read-only
unless directory changes are explicitly intended.

Production still starts through `powerview ... --web`. Restart an already running
web session after Python/template changes; normal Flask production mode caches
Jinja templates. A hard browser refresh may be needed for asset changes within
the same application release.

### Users search options

The Filters popover sends Get-DomainUser options through the shared directory
adapter. Selected filters are combined by the backend; advanced controls provide
identity, group membership, department, search base, scope, and an additional LDAP
filter. Apply runs the query. Clear resets the draft; Apply confirms it. Escape
and outside clicks discard drafts. Filters are session-local and remain active
when refreshing or changing Fields. The toolbar text filter only narrows loaded
results across visible fields.

The Protected accounts option sends `admincount: true` (`adminCount=1`). This
marker may persist after privileged membership is removed and does not establish
current administrative access. Select the `memberOf` direct-groups column in
Fields to show group names with full DNs on hover; primary and nested groups are
not included.

Search integration checks (all directory requests intercepted):

```sh
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/users-search.browser.cjs
```

### Moving objects

The `distinguishedName` attribute has a Move object action in the shared object
panel. It uses the same dialog as Explorer's Move button and sends the destination
container DN to `/api/set/domainobjectdn`. The endpoint preserves the object's RDN;
this action moves the object and does not rename it. Naming-context roots, moves
into the object's own subtree, and moves across naming contexts are rejected.

Failed writes preserve the destination input. On success, the panel follows the
new DN, Explorer refreshes both parents, directory grids reload their results, and
the Dashboard refreshes its snapshot. The DN remains protected from ordinary
attribute writes.

```sh
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/move-object.browser.cjs
```

### Password resets

User and computer detail panels expose a key action for resetting the selected
account's password. The shared dialog confirms the new password and calls
`set/domainuserpassword` or `set/domaincomputerpassword` with the object's DN.
Computer resets include a domain-trust warning. Failed requests stay in the
dialog; successful resets refresh the object. Closing the dialog clears its
password fields.

Browser checks intercept all directory requests:

```sh
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/reset-password.browser.cjs
```

### ACL changes

The shared object panel's Security tab offers Add access entry and a row trash
action on hover or keyboard focus (always visible on touch devices). Both use the existing `/api/{add,remove}/domainobjectacl` endpoints, with
the inspected DN fixed as `targetidentity`. Principal lookup suggests directory
security principals; names, full DNs and well-known SIDs can also be entered.

Choose a rights preset or a custom rights GUID, Allow/Deny, and this-object or
inheritable scope. Prevent deletion always uses Deny. DCSync represents two
replication rights. Custom GUIDs represent extended rights, except the member
attribute GUID, which uses read/write property permissions.

Row removal sends `{targetidentity, ace: {index, ace, dacl}}` to
`/api/remove/domainobjectacl`. The nested `ace` and `dacl` values are SHA-256
fingerprints supplied as `RemovalIdentity` when ACL enumeration requests
`include_ace_identity: true`. The Security tab opts in; ordinary CLI and
whole-domain enumeration do not compute or return these fingerprints. The backend reads
a fresh descriptor and checks the index and both fingerprints before removing
one occurrence. Identical duplicates, arbitrary masks, class restrictions and
other ACE bytes are preserved. Stale selections require a refresh; inherited
entries must be changed on their source object and have no trash action.

The check covers changes made since enumeration; the LDAP read and write are
separate operations, not an atomic compare-and-swap. The existing principal and
rights parameters remain available for preset-based CLI/API removal. Exact
selection cannot be mixed with those parameters. Failed writes leave the row
visible; confirmed writes trigger a fresh Security read.

```sh
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/acl-editor.browser.cjs
```

### Dashboard

The dashboard collects read-only summaries from
`GET /api/dashboard/{domain,inventory,users,computers}` using the current session.
Opening the page may reuse cached results; Refresh adds `fresh=1` to read the directory
again. `days` (30, 60, 90 or 180; default 90) sets the inactivity threshold.
Sources load sequentially and fail independently. Refresh starts a new collection;
the dashboard does not poll or retry directory reads automatically. A domain change
during collection discards the mixed snapshot.

Inventory counts cover returned objects. Review signals include enabled-account
password flags, user SPNs, adminCount, computer delegation, and replicated logons
older than the selected threshold. Unknown account state is reported separately; missing logon
timestamps are excluded from inactivity signals. These are configuration signals,
not vulnerability verdicts. Domain policy excludes fine-grained overrides, and
controller inventory does not test reachability or replication.

Each signal keeps its total count and up to 100 object samples. The evidence table
filters those samples in a scrollable list. Object links open the shared details
panel without leaving the dashboard; inventory links still navigate to their pages.
The panel retains an explicit Open in Explorer link, and modified clicks preserve
normal link navigation. Saved object changes refresh the snapshot. The desktop
review area stays at a fixed height; its signals and evidence scroll independently.
On mobile, signals form a two-column list and the evidence list has a maximum height. Controller and trust
lists also retain only the first 100 objects; their counts cover all returned
objects. These limits bound response samples, not the underlying directory reads.
Snapshot export contains
the summaries, sample evidence, source timestamps, interpretation notes, and errors.
No password secrets are requested. LDAP errors and incomplete results are shown as
unavailable sources rather than zero counts.

Checks use synthetic data and intercept all browser API requests:

```sh
python -m unittest tests.test_dashboard
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/dashboard.browser.cjs
```

### Pathfinder

Target icons use LDAP `objectClass` returned once per object in the existing ACL
response. They share the object panel's class-to-icon mapping; missing or unknown
classes use the generic object icon, with no additional lookup requests.

`/pathfinder` uses the shared list-page layout: a compact query form above a
scrollable ACE table, with a separate evidence panel for the selected row.
The form has optional Target and Principal fields and Group depth (0–5,
default 2). Typing two or more characters in Principal suggests security
principals (`objectSid` present); Target suggests any object. Suggestions
prefix-match `name` or `sAMAccountName`, return at most 20 objects through
`size_limit`, and choosing one fills the field with its distinguished name. There are no tips or result summaries underneath the form.

Opening the page performs no ACL search. Submitted queries are written to the
URL as `target`, `principal` and `depth`, and a page opened from that URL
restores the form without searching. **Find** explicitly submits
`POST /api/get/domainobjectacl` through the existing PowerView session. Target
maps to `identity`; leaving it blank omits Identity and searches visible domain objects for the
specified principal. At least one of Target or Principal is required. This UI
guard does not impose a server-side result limit; broad targets or principals
can still produce large results. Principal maps to `security_identifier`; leaving it blank shows
all returned trustees. Group depth follows the principal's `memberOf` expansion
using the existing command semantics. Requests also set `resolveguids: true`
and `no_vuln_check: true`. Ordinary searches permit cached data; Refresh repeats
the submitted query with `no_cache: true`. An unresolved or ambiguous target or principal,
or a scope with no readable security descriptors, returns the backend's error
message instead of an empty result. Cancel stops browser waiting, while
LDAP work already started may continue on the server. Escape on the focused
Cancel button also cancels.

Each returned ACE becomes a distinct row, including multiple ACEs on one target.
When a principal is submitted, the backend adds `GrantedVia` to each ACE: the
group that grants it through `memberOf` expansion, or `Direct`. The CLI prints
the same field and is off by default; add it from **Fields** for principal
queries. **ACEType** shows the same values as the CLI, such as
`ACCESS_ALLOWED_OBJECT_ACE` or `ACCESS_DENIED_ACE`, as green allow and red deny pills.
**Rights**, **ACEFlags**, **AccessMask** and **ObjectAceFlags** show each value
as a neutral chip on one line. Chips that do not fit collapse into a `+N` chip,
and the full list shows on hover; double-clicking the column edge fits every
chip. The same chip columns are used for the certificate template authority,
EKU, principal and flag columns.
**Scope** is derived as `Explicit` or `Inherited` from `ACEFlags`. The shared
table supports sorting,
local text and column filters, configurable fields and column widths. Selecting
a row opens its ACE fields in a fixed order, an Explorer link to the target and
**Find all ACEs on this target**, which replaces the query with that target and
any principal. **Export rows** downloads the filtered rows as JSON with
query metadata, timestamp, filtered-row scope and interpretation notes. Filenames include the
export time. Table operations and evidence
selection do not issue another ACL search.

Results are observed ACE evidence, not an effective-access calculation or
complete attack-path enumeration. An allow entry does not prove control;
inspect deny entries, flags and object-specific scope together. Unreadable
security descriptors and unsupported ACEs may be omitted, so an empty result
does not establish absence of access. Loading, empty, filtered-empty, failed
and cancelled searches have distinct table states.

Implementation lives in `templates/pages/pathfinder.html`,
`static/css/pages/pathfinder.css`, `static/js/pages/pathfinder.js`,
`static/js/pages/pathfinder/{records,columns}.js`, and the shared grid's
`row-details.js` adapter. It uses Jinja, native JavaScript and existing controls,
icons and theme tokens. No graph renderer or separate Pathfinder backend is
required.

Unit checks cover ACE normalization, derived fields and malformed responses. Browser checks
intercept API requests with synthetic fixtures. Start the shell preview on port
5011, then run:

```sh
node --test powerview/web/front-end/tests/pathfinder.test.mjs
EXPLORER_URL=http://127.0.0.1:5011 \
  node powerview/web/front-end/tests/pathfinder.browser.cjs
```

`EXPLORER_URL` defaults to `http://127.0.0.1:5011`. `PLAYWRIGHT_MODULE` can point to
an installed Playwright module. Set `PATHFINDER_SCREENSHOT_DIR` to capture desktop
light, desktop dark and mobile light states.
