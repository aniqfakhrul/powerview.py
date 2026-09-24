"""Flask integration for the frontend; independent of directory connections."""
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from flask import Flask, render_template, url_for

from powerview._version import __version__

FRONTEND_ROOT = Path(__file__).resolve().parent / "front-end"


@dataclass(frozen=True)
class Page:
    endpoint: str
    path: str
    title: str
    section: str = "Directory"
    template: str = "pages/placeholder.html"


PAGES = (
    Page("index", "/", "Explorer", "Workspace", "pages/explorer.html"),
    Page("dashboard", "/dashboard", "Dashboard", "Workspace"),
    Page("graph", "/graph", "Graph", "Workspace"),
    Page("users", "/users", "Users", template="pages/users.html"),
    Page("computers", "/computers", "Computers", template="pages/computers.html"),
    Page("groups", "/groups", "Groups"),
    Page("dns", "/dns", "DNS"),
    Page("ca", "/ca", "Certificate authorities"),
    Page("ou", "/ou", "Organizational units"),
    Page("gpo", "/gpo", "Group policies"),
    Page("smb", "/smb", "SMB browser"),
    Page("utils", "/utils", "Utilities", "Tools"),
)


def create_web_app(import_name):
    """Resolve assets relative to this package, never the working directory."""
    app = Flask(
        import_name,
        template_folder=str(FRONTEND_ROOT / "templates"),
        static_folder=str(FRONTEND_ROOT / "static"),
        static_url_path="/static",
    )
    app.jinja_env.globals["asset_url"] = asset_url
    return app


def asset_url(filename):
    """Generate prefix-aware asset URLs with a release cache key."""
    return url_for("static", filename=filename, v=__version__)


def render_page(page):
    """Supply shared shell context in one place without querying the backend."""
    return render_template(
        page.template, page=page, pages=PAGES, version=__version__,
        sections=tuple(dict.fromkeys(item.section for item in PAGES)),
    )


def register_frontend(add_route):
    """Use the server's route registrar so page authentication stays consistent."""
    for page in PAGES:
        add_route(page.path, page.endpoint, partial(render_page, page), methods=["GET"])
