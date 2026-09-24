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
    pages/placeholder.html      Other modules, awaiting implementation
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
  into it. DN-valued attributes are links that reveal the target in the tree.
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

## Backend boundary

`APIServer` owns authentication and API routes. `register_frontend` uses its
existing authentication wrapper. Static assets are public and contain no session
secrets. `asset_url` resolves deployment prefixes and adds a release cache key.
Paths resolve relative to the Python package, independent of the launch directory.
The existing `MANIFEST.in` includes templates and assets in distributions.

Other modules remain placeholders. Add a `Page` entry in `web/frontend.py`, extend
`layouts/workspace.html`, and load page-specific files in `styles`/`scripts` blocks.
Use `url_for` for navigation and `asset_url` for static assets. Keep reusable UI
in macros and focused modules; directory data enters the DOM through textContent.

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
