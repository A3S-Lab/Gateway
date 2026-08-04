#!/usr/bin/env python3
"""Validate the dependency-free GitHub Pages site."""

from __future__ import annotations

import json
import math
import re
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
    "assets/performance-comparison.json",
    "assets/performance-data.json",
    "assets/request-path-demo.gif",
    "assets/request-path-demo.svg",
    "assets/social-card.svg",
    "docs/docs.css",
    "docs/docs.js",
    "docs/index.html",
    "index.html",
    "robots.txt",
    "site.webmanifest",
    "sitemap.xml",
    "styles/base.css",
    "styles/middleware.css",
    "styles/responsive.css",
    "styles/sections.css",
)

EXPECTED_BENCHMARKS = {
    ("router_match", "highest_priority_match", 1000),
    ("router_match", "no_match", 1000),
    ("middleware_pipeline", "process_request", 10),
    ("acl_parse", "services", 300),
}


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


def validate_local_reference(
    reference: str,
    source_path: Path,
    page_ids: dict[Path, set[str]],
) -> str | None:
    parsed = urlparse(reference)
    if parsed.scheme or parsed.netloc or reference.startswith(("mailto:", "tel:")):
        return None
    if reference.startswith("#"):
        fragment = unquote(parsed.fragment)
        if fragment and fragment not in page_ids.get(source_path, set()):
            return f"missing same-page fragment #{fragment}"
        return None
    if parsed.path.startswith("/"):
        return None

    target = (source_path.parent / unquote(parsed.path)).resolve()
    try:
        target.relative_to(SITE_ROOT)
    except ValueError:
        return "local reference escapes the website directory"
    if not target.exists():
        return f"missing local file {parsed.path}"
    if target.is_dir():
        target = target / "index.html"
        if not target.is_file():
            return f"local directory {parsed.path} has no index.html"
    if parsed.fragment and target.suffix.lower() in {".html", ".htm"}:
        fragment = unquote(parsed.fragment)
        if fragment not in page_ids.get(target, set()):
            return f"missing target fragment #{fragment} in {parsed.path}"
    return None


def validate_benchmark_data(errors: list[str]) -> None:
    """Validate the published, CI-generated Criterion baseline."""

    data_path = SITE_ROOT / "assets" / "performance-data.json"
    if not data_path.is_file():
        return

    try:
        payload = json.loads(data_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        errors.append(f"invalid performance-data.json: {error}")
        return

    if payload.get("schema_version") != 1:
        errors.append("performance-data.json must use schema_version 1")

    commit = payload.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("performance-data.json has an invalid commit SHA")

    run_url = payload.get("run_url")
    if not isinstance(run_url, str) or not run_url.startswith(
        "https://github.com/A3S-Lab/Gateway/actions/runs/"
    ):
        errors.append("performance-data.json has an invalid benchmark run URL")

    methodology = payload.get("methodology")
    scope = methodology.get("scope") if isinstance(methodology, dict) else None
    if not isinstance(scope, str) or "In-process" not in scope:
        errors.append("performance-data.json must document its in-process scope")

    results = payload.get("results")
    if not isinstance(results, list):
        errors.append("performance-data.json results must be a list")
        return

    seen: set[tuple[str, str, int]] = set()
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            errors.append(f"performance result {index} must be an object")
            continue

        key = (result.get("group"), result.get("scenario"), result.get("parameter"))
        if isinstance(key[0], str) and isinstance(key[1], str) and isinstance(key[2], int):
            seen.add(key)

        values = [
            result.get("ci95_lower_ns"),
            result.get("median_ns"),
            result.get("ci95_upper_ns"),
        ]
        if not all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value > 0
            for value in values
        ):
            errors.append(f"performance result {index} has invalid timing values")
            continue
        if not values[0] <= values[1] <= values[2]:
            errors.append(f"performance result {index} has an invalid confidence interval")

    missing = EXPECTED_BENCHMARKS - seen
    if missing:
        errors.append(f"performance-data.json is missing published cards: {sorted(missing)}")


def validate_proxy_comparison(errors: list[str]) -> None:
    """Validate the CI-generated same-host A3S Gateway and NGINX comparison."""

    data_path = SITE_ROOT / "assets" / "performance-comparison.json"
    if not data_path.is_file():
        return
    try:
        payload = json.loads(data_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        errors.append(f"invalid performance-comparison.json: {error}")
        return

    if payload.get("schema_version") != 1:
        errors.append("performance-comparison.json must use schema_version 1")
    commit = payload.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("performance-comparison.json has an invalid commit SHA")
    run_url = payload.get("run_url")
    if not isinstance(run_url, str) or not run_url.startswith(
        "https://github.com/A3S-Lab/Gateway/actions/runs/"
    ):
        errors.append("performance-comparison.json has an invalid run URL")

    methodology = payload.get("methodology")
    if not isinstance(methodology, dict):
        errors.append("performance-comparison.json is missing methodology")
    else:
        for field in ("scope", "trials", "aggregation", "threshold"):
            if not methodology.get(field):
                errors.append(f"proxy comparison methodology is missing {field!r}")

    proxies = payload.get("proxies")
    if not isinstance(proxies, dict):
        errors.append("performance-comparison.json proxies must be an object")
    else:
        for proxy in ("a3s-gateway", "nginx"):
            result = proxies.get(proxy)
            if not isinstance(result, dict):
                errors.append(f"proxy comparison is missing {proxy}")
                continue
            median = result.get("median")
            if not isinstance(median, dict):
                errors.append(f"proxy comparison is missing {proxy} medians")
                continue
            for metric in (
                "requests_per_second",
                "average_latency_us",
                "p50_latency_us",
                "p90_latency_us",
                "p99_latency_us",
            ):
                value = median.get(metric)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value <= 0
                ):
                    errors.append(f"{proxy} has an invalid {metric}")

    comparison = payload.get("comparison")
    verdicts = comparison.get("verdicts") if isinstance(comparison, dict) else None
    if not isinstance(verdicts, dict):
        errors.append("performance-comparison.json is missing verdicts")
    else:
        for metric in ("throughput", "p50_latency", "p90_latency", "p99_latency"):
            if verdicts.get(metric) not in {"better", "similar", "worse"}:
                errors.append(f"proxy comparison has an invalid {metric} verdict")


def main() -> int:
    errors: list[str] = []

    for installer in ("install.sh", "install.ps1"):
        if not (REPOSITORY_ROOT / installer).is_file():
            errors.append(f"repository installer is missing: {installer}")

    for relative_path in REQUIRED_FILES:
        if not (SITE_ROOT / relative_path).is_file():
            errors.append(f"required file is missing: {relative_path}")

    html_paths = [
        SITE_ROOT / relative
        for relative in ("index.html", "404.html", "docs/index.html")
    ]
    parsed_pages: dict[Path, SiteHTMLParser] = {}
    page_ids: dict[Path, set[str]] = {}
    page_html: dict[Path, str] = {}
    for html_path in html_paths:
        if not html_path.is_file():
            continue
        parser = SiteHTMLParser()
        content = html_path.read_text(encoding="utf-8")
        parser.feed(content)
        parsed_pages[html_path] = parser
        page_ids[html_path] = set(parser.ids)
        page_html[html_path] = content

    index_path = SITE_ROOT / "index.html"
    index_html = page_html.get(index_path)
    if index_html is not None:

        for marker in (
            "AI Native Traffic Layer",
            "A3S Gateway routes HTTP, SSE, WebSocket, gRPC, TCP, and UDP",
            "assets/request-path-demo.gif",
            'id="performance"',
            'id="comparison"',
            "data-benchmark-group",
            "data-config-demo",
            'data-config-step="service"',
            'id="middleware"',
            "MiddlewareRegistry",
            "Gateway::with_middlewares",
            'id="data-performance-verdict"',
            "docs/",
            "https://a3s-lab.github.io/Gateway/install.sh",
            "https://a3s-lab.github.io/Gateway/install.ps1",
            "machine-only Node API",
        ):
            if marker not in index_html:
                errors.append(f"product story marker is missing: {marker}")

    docs_path = SITE_ROOT / "docs" / "index.html"
    docs_html = page_html.get(docs_path)
    if docs_html is not None:
        for marker in (
            "A3S Gateway documentation",
            'id="configuration"',
            'id="middleware"',
            'id="custom-middleware"',
            "MiddlewareRegistry",
            "Gateway::with_middlewares",
            "rate-limit-redis",
            "dynamic libraries or Wasm plugins",
            'id="performance"',
            "A3S Cloud",
        ):
            if marker not in docs_html:
                errors.append(f"documentation marker is missing: {marker}")

    for html_path, parser in parsed_pages.items():
        duplicates = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
        if duplicates:
            relative = html_path.relative_to(SITE_ROOT)
            errors.append(f"duplicate HTML ids in {relative}: {', '.join(duplicates)}")

        for tag, attribute, reference in parser.references:
            if problem := validate_local_reference(reference, html_path, page_ids):
                relative = html_path.relative_to(SITE_ROOT)
                errors.append(f"{relative}: {tag}[{attribute}={reference!r}]: {problem}")

        if parser.images_without_alt:
            errors.append(f"all img elements in {html_path.name} must define alt text")

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

    validate_benchmark_data(errors)
    validate_proxy_comparison(errors)

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
