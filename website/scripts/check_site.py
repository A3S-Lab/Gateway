#!/usr/bin/env python3
"""Validate the dependency-free GitHub Pages site."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse


SITE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SITE_ROOT.parent
REQUIRED_FILES = (
    ".nojekyll",
    "404.html",
    "app.js",
    "assets/mark.svg",
    "assets/request-path-demo.gif",
    "assets/request-path-demo.svg",
    "assets/social-card.svg",
    "index.html",
    "robots.txt",
    "site.webmanifest",
    "sitemap.xml",
    "styles/base.css",
    "styles/responsive.css",
    "styles/sections.css",
)


class SiteHTMLParser(HTMLParser):
    """Collect IDs, links, and accessible image metadata."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.references: list[tuple[str, str, str]] = []
        self.images_without_alt: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if element_id := attributes.get("id"):
            self.ids.append(element_id)

        for attribute in ("href", "src"):
            if reference := attributes.get(attribute):
                self.references.append((tag, attribute, reference))

        if tag == "img" and "alt" not in attributes:
            self.images_without_alt.append(self.get_starttag_text())


def validate_local_reference(reference: str, ids: set[str]) -> str | None:
    parsed = urlparse(reference)
    if parsed.scheme or parsed.netloc or reference.startswith(("mailto:", "tel:")):
        return None
    if reference.startswith("#"):
        fragment = unquote(parsed.fragment)
        if fragment and fragment not in ids:
            return f"missing same-page fragment #{fragment}"
        return None
    if parsed.path.startswith("/"):
        return None

    target = (SITE_ROOT / unquote(parsed.path)).resolve()
    try:
        target.relative_to(SITE_ROOT)
    except ValueError:
        return "local reference escapes the website directory"
    if not target.exists():
        return f"missing local file {parsed.path}"
    return None


def main() -> int:
    errors: list[str] = []

    for installer in ("install.sh", "install.ps1"):
        if not (REPOSITORY_ROOT / installer).is_file():
            errors.append(f"repository installer is missing: {installer}")

    for relative_path in REQUIRED_FILES:
        if not (SITE_ROOT / relative_path).is_file():
            errors.append(f"required file is missing: {relative_path}")

    index_path = SITE_ROOT / "index.html"
    if index_path.is_file():
        parser = SiteHTMLParser()
        index_html = index_path.read_text(encoding="utf-8")
        parser.feed(index_html)

        for marker in (
            "A3S Gateway proxies HTTP, SSE, WebSocket, gRPC, TCP, and UDP",
            "assets/request-path-demo.gif",
            "https://a3s-lab.github.io/Gateway/install.sh",
            "https://a3s-lab.github.io/Gateway/install.ps1",
            "machine-only Node API",
        ):
            if marker not in index_html:
                errors.append(f"product story marker is missing: {marker}")

        duplicates = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
        if duplicates:
            errors.append(f"duplicate HTML ids: {', '.join(duplicates)}")
        ids = set(parser.ids)

        for tag, attribute, reference in parser.references:
            if problem := validate_local_reference(reference, ids):
                errors.append(f"{tag}[{attribute}={reference!r}]: {problem}")

        if parser.images_without_alt:
            errors.append("all img elements must define alt text")

    manifest_path = SITE_ROOT / "site.webmanifest"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            errors.append(f"invalid site.webmanifest: {error}")
        else:
            for field in ("name", "short_name", "start_url", "icons"):
                if not manifest.get(field):
                    errors.append(f"site.webmanifest is missing {field!r}")

    sitemap_path = SITE_ROOT / "sitemap.xml"
    if sitemap_path.is_file():
        try:
            ET.parse(sitemap_path)
        except (ET.ParseError, OSError) as error:
            errors.append(f"invalid sitemap.xml: {error}")

    if errors:
        print("Website validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Website validation passed ({len(REQUIRED_FILES)} site files and 2 installers)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
