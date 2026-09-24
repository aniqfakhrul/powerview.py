# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Practitioners working inside an Active Directory domain through an authenticated PowerView.py session: they launch the CLI with `--web` and use the browser workspace alongside the interactive shell. Inferred from the repository README; the primary-user question was not answered in the interview.

## Product Purpose
PowerView.py is a Python alternative to PowerView.ps1. Its main goal is an interactive session over a persistent LDAP (or LDAPS, GC, ADWS) connection without re-authenticating for every query. The web workspace exposes the same session as a visual interface.

## Positioning
The web UI rides the exact session the CLI already holds, so every page reflects live directory state through PowerView's own modules rather than a separate collector or offline snapshot.

## Operating Context
- Started locally via `powerview <target> --web [--web-host] [--web-port] [--web-auth user:pass]`; optional HTTP basic auth.
- Used on a laptop or desktop next to a terminal; the directory can be large, so views page and filter rather than load everything.
- Backend is Flask (`powerview/web/api/server.py`); pages are server-rendered Jinja with native ES modules.

## Capabilities and Constraints
- Explorer (confirmed scope): browse every object in the left-hand directory tree and inspect the selected object's attributes in the right-hand pane (no results table), edit attribute values, create, move, and delete objects.
- API contracts are per-endpoint, not one envelope; mutations must never be retried automatically.
- No Node build, CDN, external fonts, or frontend framework; assets ship inside the Python package.
- Light and dark themes, following the OS setting (confirmed).

## Brand Commitments
- Name: PowerView.py; existing mark at `powerview/web/front-end/static/images/mark.svg`.
- Visual reference the user made binding: Airtable's clean grid-and-record interface (`ref/`), rendered compact and classic like a desktop directory browser (AD Explorer); premium neutral dark mode, not blue-tinted.

## Evidence on Hand
No sample directory data ships with the repo; the UI must never display fabricated objects.

## Product Principles
- Live truth: show what the directory returns, with honest loading, empty, and error states.
- Destructive actions are deliberate: confirm before deleting or moving, never retry mutations.
- Density with calm: many objects and attributes on screen, organized so scanning stays easy.
- Same session, same behavior: the UI mirrors PowerView module semantics rather than inventing its own.
