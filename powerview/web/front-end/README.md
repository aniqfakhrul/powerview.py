# Frontend foundation

PowerView uses server-rendered Flask/Jinja pages with local CSS and native JavaScript
modules. No Node build, CDN, external fonts, or frontend framework is required.
This stage provides the shell only: every page is explicitly a placeholder and
makes no directory requests. The visual direction is compact, light, and workspace
oriented, with shared design tokens rather than page-specific styling.

## Structure

```text
web/frontend.py                 Flask creation, page registry, rendering, asset URLs
front-end/
  templates/
    base.html                   Document head and shared stylesheet/module loading
    layouts/workspace.html      Shell composition and main content landmark
    partials/                   Sidebar and header (shared context)
    components/                 Reusable Jinja macros (explicit arguments)
    pages/                      Page content; currently a shared placeholder
  static/
    css/
      main.css                  Single stylesheet entry point
      tokens.css                Color, spacing, type, radius, and width tokens
      base.css                  Element defaults and keyboard focus
      layout.css                Shell, navigation, and responsive layout
      components.css            Reusable visual components
    js/app.js                   Shared ES-module entry point
    images/                     Local image assets
```

Add `static/js/pages/`, `static/js/components/`, `static/js/core/`, and
`static/css/pages/` when their first real implementations are needed. Avoid empty
abstraction layers and generic utility files without concrete consumers.

## Adding a page

1. Add or update its `Page` entry in `web/frontend.py`. Paths, endpoint names,
   navigation labels, sections, and template selection live in this registry.
2. Create `templates/pages/<name>.html` extending `layouts/workspace.html` and
   override `content`. Use macros for repeated UI and includes for shell fragments.
3. Load page-specific styles and modules through the `styles` and `scripts` blocks.
   Use `asset_url('js/pages/<name>.js')` for assets and `url_for('<endpoint>')`
   for navigation; never hardcode deployment-root URLs.
4. Keep business logic in page modules and reusable behavior in focused modules.
   Use native ES imports, no window globals, inline handlers, or inline scripts.

`base.html` owns shared asset loading. `asset_url` adds the application release
as a cache key; development asset changes can require a hard refresh within the
same release. Static paths resolve from the installed Python package, independent
of the launch directory. The existing `MANIFEST.in` graft includes these assets.

## Backend boundary

`APIServer` owns authentication and all API routes. `register_frontend` uses its
authenticated registrar, preserving existing page URLs and endpoint names. Static
assets are public Flask assets and must contain no credentials or session data.
Rendering the shell does not call the directory connection.

Future feature modules should account for the existing API contracts:

- `/api/get/<method>` accepts GET parameters or POST JSON. Other operation prefixes
  accept POST JSON. Responses are serialized backend values, not one common envelope.
- `/api/execute` returns `result` and `pv_args`; failures generally contain `error`.
- `/api/connectioninfo`, `/api/get/domaininfo`, and server info/schema expose context.
- `/api/logs` is paginated JSON; `/api/smb/search-stream` is server-sent events.
- SMB endpoints have their own request/response shapes and session requirements.

Introduce a shared request client when implementing the first API-backed feature,
with explicit error handling and cancellation. Do not automatically retry mutations.
The old user/computer filter metadata was embedded in page render methods; define
those contracts alongside the corresponding feature when rebuilding it.

## UI conventions

Use the shared tokens; keep compact desktop spacing and readable labels. Navigation
becomes a horizontally scrollable row below 720px, usable without JavaScript. Keep
semantic landmarks, a skip link, visible focus, and `aria-current` navigation.
Use explicit empty, loading, error, and populated states when adding data features.
Avoid fake data, inert action buttons, and connection indicators without live state.

## Local shell preview

With the normal project dependencies installed:

```python
from powerview.web.frontend import create_web_app, register_frontend

app = create_web_app(__name__)
register_frontend(app.add_url_rule)
app.run(host="127.0.0.1", port=5001)
```

This standalone preview has no API or authentication and needs no directory session.
Production continues to start through `APIServer`.
