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
    "assets/fonts/LICENSE-Geist.txt",
    "assets/fonts/geist-latin-wght-normal.woff2",
    "assets/fonts/geist-mono-latin-wght-normal.woff2",
    "assets/performance-comparison.json",
    "assets/performance-data.json",
    "assets/phosphor-icons-LICENSE.txt",
    "assets/phosphor-icons.svg",
    "assets/request-path-demo.gif",
    "assets/request-path-demo.svg",
    "assets/social-card.svg",
    "docs/docs.css",
    "docs/docs.js",
    "docs/index.html",
    "docs/next/index.html",
    "docs/versions.json",
    "index.html",
    "robots.txt",
    "site.webmanifest",
    "sitemap.xml",
    "traffic-profiles.js",
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

EXPECTED_TRAFFIC_PROFILES = {
    "http1-small",
    "https-http1",
    "https-http2",
    "grpc-unary",
    "sse-finite",
    "websocket-echo",
    "tcp-echo",
    "udp-echo",
    "openai-json",
    "openai-stream",
}

EXPECTED_AI_PROFILES = {
    "stream-overhead-c1",
    "stream-overhead-c64",
    "stream-paced-c16",
    "stream-paced-c64",
    "stream-long-output",
    "completions-paced-c16",
    "prompt-32k",
    "prompt-256k",
}
AI_DISTRIBUTIONS = (
    "ttft",
    "inter_token_latency",
    "time_per_output_token",
    "end_to_end",
)

# Performance workflows publish this artifact and the Pages workflow preserves
# the latest valid copy while deploying hand-authored site changes. It is
# intentionally absent from a fresh checkout, so links to it are valid even
# before the first benchmark run for a commit.
GENERATED_SITE_FILES = {
    "assets/ai-gateway-comparison.json",
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
    relative_target = target.relative_to(SITE_ROOT).as_posix()
    if not target.exists() and relative_target in GENERATED_SITE_FILES:
        return None
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


def validate_proxy_results(
    errors: list[str],
    proxies: object,
    metrics: tuple[str, ...],
    context: str,
) -> None:
    if not isinstance(proxies, dict):
        errors.append(f"{context} proxies must be an object")
        return
    for proxy in ("a3s-gateway", "nginx"):
        result = proxies.get(proxy)
        if not isinstance(result, dict):
            errors.append(f"{context} is missing {proxy}")
            continue
        trials = result.get("trials")
        median = result.get("median")
        if not isinstance(trials, list) or not trials:
            errors.append(f"{context} is missing {proxy} trials")
        if not isinstance(median, dict):
            errors.append(f"{context} is missing {proxy} medians")
            continue
        for metric in metrics:
            value = median.get(metric)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                errors.append(f"{context} {proxy} has an invalid {metric}")


def validate_positions(
    errors: list[str], comparison: object, schema_version: int, context: str
) -> None:
    positions = comparison.get("positions") if isinstance(comparison, dict) else None
    if not isinstance(positions, dict):
        errors.append(f"{context} is missing positions")
        return
    if schema_version == 2:
        allowed = {"a3s_leads", "within_threshold", "nginx_leads"}
        for metric in ("throughput", "p50_latency", "p90_latency", "p99_latency"):
            if positions.get(metric) not in allowed:
                errors.append(f"{context} has an invalid {metric} position")
        return

    if positions.get("throughput") not in {
        "a3s_higher",
        "within_threshold",
        "nginx_higher",
    }:
        errors.append(f"{context} has an invalid throughput position")
    for metric in ("p50_latency", "p90_latency", "p99_latency"):
        if positions.get(metric) not in {
            "a3s_lower",
            "within_threshold",
            "nginx_lower",
        }:
            errors.append(f"{context} has an invalid {metric} position")


def validate_proxy_comparison(errors: list[str]) -> None:
    """Validate the CI-generated same-host multi-protocol comparison."""

    data_path = SITE_ROOT / "assets" / "performance-comparison.json"
    if not data_path.is_file():
        return
    try:
        payload = json.loads(data_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        errors.append(f"invalid performance-comparison.json: {error}")
        return

    schema_version = payload.get("schema_version")
    if schema_version not in {2, 3}:
        errors.append("performance-comparison.json must use schema_version 2 or 3")
        return
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
        if schema_version == 3 and not methodology.get("warmup_seconds"):
            errors.append("proxy comparison methodology is missing 'warmup_seconds'")
        if schema_version == 3 and not methodology.get("completion_policy"):
            errors.append("schema 3 proxy methodology is missing 'completion_policy'")

    validate_proxy_results(
        errors,
        payload.get("proxies"),
        (
            "requests_per_second",
            "average_latency_us",
            "p50_latency_us",
            "p90_latency_us",
            "p99_latency_us",
        ),
        "proxy comparison",
    )
    validate_positions(
        errors,
        payload.get("comparison"),
        schema_version,
        "proxy comparison",
    )

    if schema_version == 2:
        return
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        errors.append("performance-comparison.json is missing traffic profiles")
        return
    profile_ids = set(profiles)
    missing_profiles = EXPECTED_TRAFFIC_PROFILES - profile_ids
    if missing_profiles:
        errors.append(f"proxy comparison is missing profiles: {sorted(missing_profiles)}")
    unexpected_profiles = profile_ids - EXPECTED_TRAFFIC_PROFILES
    if unexpected_profiles:
        errors.append(
            f"proxy comparison has unexpected profiles: {sorted(unexpected_profiles)}"
        )
    for profile_id in EXPECTED_TRAFFIC_PROFILES & profile_ids:
        profile = profiles[profile_id]
        if not isinstance(profile, dict):
            errors.append(f"proxy profile {profile_id} must be an object")
            continue
        for field in (
            "label",
            "traffic",
            "unit",
            "load_generator",
            "capability_alignment",
            "workload",
        ):
            if not profile.get(field):
                errors.append(f"proxy profile {profile_id} is missing {field}")
        validate_proxy_results(
            errors,
            profile.get("proxies"),
            (
                "success_rate",
                "operations_per_second",
                "average_latency_us",
                "p50_latency_us",
                "p90_latency_us",
                "p99_latency_us",
            ),
            f"proxy profile {profile_id}",
        )
        validate_positions(
            errors,
            profile.get("comparison"),
            schema_version,
            f"proxy profile {profile_id}",
        )


def validate_ai_distribution(
    errors: list[str],
    distribution: object,
    expected_samples: int,
    context: str,
    sample_field: str,
) -> None:
    if not isinstance(distribution, dict):
        errors.append(f"{context} must be an object")
        return
    if distribution.get(sample_field) != expected_samples:
        errors.append(f"{context} has an invalid {sample_field}")
    values = [
        distribution.get(field)
        for field in (
            "min_us",
            "p50_us",
            "p90_us",
            "p95_us",
            "p99_us",
            "max_us",
        )
    ]
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
        for value in values
    ):
        errors.append(f"{context} has invalid latency values")
    elif values != sorted(values):
        errors.append(f"{context} latency percentiles are not monotonic")


def validate_ai_comparison(errors: list[str]) -> None:
    """Validate the optional CI-generated token-aware AI comparison."""

    data_path = SITE_ROOT / "assets" / "ai-gateway-comparison.json"
    if not data_path.is_file():
        return
    try:
        payload = json.loads(data_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        errors.append(f"invalid ai-gateway-comparison.json: {error}")
        return

    if not isinstance(payload, dict):
        errors.append("ai-gateway-comparison.json must contain an object")
        return
    if payload.get("schema_version") != "a3s.gateway.ai-comparison.v1":
        errors.append("ai-gateway-comparison.json has an unsupported schema")
        return
    commit = payload.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("ai-gateway-comparison.json has an invalid commit SHA")
    run_url = payload.get("run_url")
    if not isinstance(run_url, str) or not run_url.startswith(
        "https://github.com/A3S-Lab/Gateway/actions/runs/"
    ):
        errors.append("ai-gateway-comparison.json has an invalid run URL")

    methodology = payload.get("methodology")
    if not isinstance(methodology, dict):
        errors.append("ai-gateway-comparison.json is missing methodology")
        return
    for field in (
        "scope",
        "trials",
        "aggregation",
        "clock",
        "token_definition",
        "correctness_gate",
        "nginx_streaming",
        "threshold",
    ):
        if not methodology.get(field):
            errors.append(f"AI comparison methodology is missing {field!r}")
    expected_trials = methodology.get("trials")
    if (
        not isinstance(expected_trials, int)
        or isinstance(expected_trials, bool)
        or expected_trials <= 0
    ):
        errors.append("AI comparison trial count must be a positive integer")
        return

    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        errors.append("ai-gateway-comparison.json is missing profiles")
        return
    if set(profiles) != EXPECTED_AI_PROFILES:
        errors.append(
            "AI comparison profile set does not match the published core matrix"
        )
    for profile_id, profile in profiles.items():
        context = f"AI profile {profile_id}"
        if not isinstance(profile, dict):
            errors.append(f"{context} must be an object")
            continue
        scenario = profile.get("scenario")
        if not isinstance(scenario, dict):
            errors.append(f"{context} is missing its scenario")
            continue
        requests = scenario.get("requests")
        tokens = scenario.get("token_count")
        concurrency = scenario.get("concurrency")
        prompt_bytes = scenario.get("prompt_bytes")
        if not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in (requests, tokens, concurrency, prompt_bytes)
        ):
            errors.append(f"{context} has invalid request, token, or load values")
            continue

        products = profile.get("products")
        if not isinstance(products, dict):
            errors.append(f"{context} is missing products")
            continue
        for product in ("a3s-gateway", "nginx"):
            result = products.get(product)
            product_context = f"{context} {product}"
            if not isinstance(result, dict):
                errors.append(f"{product_context} result is missing")
                continue
            trials = result.get("trials")
            median = result.get("median")
            if not isinstance(trials, list) or len(trials) != expected_trials:
                errors.append(f"{product_context} has an invalid raw trial count")
                continue
            if not isinstance(median, dict):
                errors.append(f"{product_context} is missing medians")
                continue
            for index, trial in enumerate(trials, 1):
                trial_context = f"{product_context} trial {index}"
                if not isinstance(trial, dict):
                    errors.append(f"{trial_context} must be an object")
                    continue
                if (
                    trial.get("schema_version")
                    != "a3s.gateway.ai-comparison.trial.v1"
                    or trial.get("product") != product
                    or trial.get("trial") != index
                    or trial.get("completed_requests") != requests
                    or trial.get("failed_requests") != 0
                    or trial.get("success_rate") != 1.0
                    or trial.get("completed_tokens") != requests * tokens
                ):
                    errors.append(f"{trial_context} failed the correctness gate")
                for distribution in AI_DISTRIBUTIONS:
                    sample_count = requests
                    if distribution == "inter_token_latency":
                        sample_count = requests * (tokens - 1)
                    validate_ai_distribution(
                        errors,
                        trial.get(distribution),
                        sample_count,
                        f"{trial_context} {distribution}",
                        "samples",
                    )
            for field in ("streams_per_second", "token_goodput_per_second"):
                value = median.get(field)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value <= 0
                ):
                    errors.append(f"{product_context} has invalid median {field}")
            for distribution in AI_DISTRIBUTIONS:
                sample_count = requests
                if distribution == "inter_token_latency":
                    sample_count = requests * (tokens - 1)
                validate_ai_distribution(
                    errors,
                    median.get(distribution),
                    sample_count,
                    f"{product_context} median {distribution}",
                    "samples_per_trial",
                )
        comparison = profile.get("comparison")
        if not isinstance(comparison, dict):
            errors.append(f"{context} is missing comparison ratios")
            continue
        ratio_fields = (
            "a3s_to_nginx_token_goodput_ratio",
            "a3s_to_nginx_stream_rate_ratio",
            "a3s_to_nginx_ttft_p50_ratio",
            "a3s_to_nginx_ttft_p99_ratio",
            "a3s_to_nginx_inter_token_latency_p50_ratio",
            "a3s_to_nginx_inter_token_latency_p99_ratio",
            "a3s_to_nginx_time_per_output_token_p50_ratio",
            "a3s_to_nginx_time_per_output_token_p99_ratio",
            "a3s_to_nginx_end_to_end_p50_ratio",
            "a3s_to_nginx_end_to_end_p99_ratio",
        )
        for field in ratio_fields:
            value = comparison.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                errors.append(f"{context} has invalid comparison ratio {field}")


def validate_documentation_versions(
    errors: list[str],
    page_html: dict[Path, str],
    page_ids: dict[Path, set[str]],
) -> None:
    """Validate the documentation registry, routes, and section parity."""

    registry_path = SITE_ROOT / "docs" / "versions.json"
    if not registry_path.is_file():
        return
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        errors.append(f"invalid docs/versions.json: {error}")
        return

    if not isinstance(registry, dict) or registry.get("schemaVersion") != 1:
        errors.append("docs/versions.json must use schemaVersion 1")
        return
    default = registry.get("default")
    versions = registry.get("versions")
    if not isinstance(default, str) or not isinstance(versions, list) or not versions:
        errors.append("docs/versions.json must define a default and versions")
        return

    normalized: list[tuple[str, str, str, str]] = []
    for index, version in enumerate(versions):
        if not isinstance(version, dict):
            errors.append(f"documentation version {index} must be an object")
            continue
        values = tuple(version.get(field) for field in ("id", "label", "channel", "path"))
        if not all(isinstance(value, str) and value for value in values):
            errors.append(f"documentation version {index} has incomplete metadata")
            continue
        version_id, label, channel, route = values
        if channel not in {"stable", "development", "archived"}:
            errors.append(f"documentation version {version_id!r} has an invalid channel")
        normalized.append((version_id, label, channel, route))

    version_ids = [version[0] for version in normalized]
    if len(set(version_ids)) != len(version_ids):
        errors.append("docs/versions.json contains duplicate version ids")
    if not version_ids or version_ids[0] != default:
        errors.append("the default documentation version must be listed first")
    if "next" not in version_ids:
        errors.append("the next documentation channel is not registered")

    cargo_manifest = (REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    package_version = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', cargo_manifest, re.MULTILINE)
    if not package_version:
        errors.append("Cargo.toml package version could not be read")
    else:
        release_version = ".".join(package_version.groups())
        expected_default = f"v{package_version.group(1)}.{package_version.group(2)}"
        if default != expected_default:
            errors.append(
                f"documentation default {default!r} does not match Cargo series {expected_default!r}"
            )
        stable_content = page_html.get(SITE_ROOT / "docs" / "index.html", "")
        if f"GATEWAY {release_version}" not in stable_content:
            errors.append(
                f"stable documentation does not identify package release {release_version}"
            )
        roadmap = (REPOSITORY_ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        if f"current `v{release_version}` release" not in roadmap:
            errors.append(f"ROADMAP.md does not identify current release v{release_version}")

    stable_path = SITE_ROOT / "docs" / "index.html"
    stable_sections = {
        section_id
        for section_id in page_ids.get(stable_path, set())
        if section_id not in {"docs-content", "nav-links"}
    }
    for version_id, _label, channel, route in normalized:
        if version_id == default:
            html_path = stable_path
        else:
            html_path = SITE_ROOT / "docs" / route.strip("/") / "index.html"
        content = page_html.get(html_path)
        if content is None:
            errors.append(f"documentation route for {version_id!r} is missing: {html_path.relative_to(SITE_ROOT)}")
            continue
        if f'data-doc-version="{version_id}"' not in content:
            errors.append(f"documentation route {version_id!r} does not identify its version")
        for marker in (
            "data-doc-ai-rows",
            "ai-gateway-comparison.json",
            "data-doc-ai-run",
        ):
            if marker not in content:
                errors.append(
                    f"documentation route {version_id!r} does not expose {marker!r}"
                )
        if channel == "development" and 'name="robots" content="noindex,follow"' not in content:
            errors.append(f"development documentation {version_id!r} must be noindex")
        sections = {
            section_id
            for section_id in page_ids.get(html_path, set())
            if section_id not in {"docs-content", "nav-links"}
        }
        if sections != stable_sections:
            missing = sorted(stable_sections - sections)
            extra = sorted(sections - stable_sections)
            errors.append(
                f"documentation section parity failed for {version_id!r} "
                f"(missing: {missing or 'none'}; extra: {extra or 'none'})"
            )


def main() -> int:
    errors: list[str] = []

    for installer in ("install.sh", "install.ps1"):
        if not (REPOSITORY_ROOT / installer).is_file():
            errors.append(f"repository installer is missing: {installer}")

    for relative_path in REQUIRED_FILES:
        if not (SITE_ROOT / relative_path).is_file():
            errors.append(f"required file is missing: {relative_path}")

    html_paths = [SITE_ROOT / "index.html", SITE_ROOT / "404.html"]
    html_paths.extend(sorted((SITE_ROOT / "docs").glob("**/index.html")))
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
            "AI traffic, governed and measured locally.",
            'aria-label="A3S Gateway home"',
            '<span>A3S <b>Gateway</b></span>',
            "assets/request-path-demo.gif",
            "LIVE TRAFFIC TOPOLOGY",
            'id="why-a3s"',
            'id="comparison"',
            'id="features"',
            'id="performance"',
            'id="middleware"',
            'id="config"',
            'id="architecture"',
            'id="deploy"',
            "Model-aware policy",
            "Stream-native limits",
            "Health-aware recovery",
            "Atomic desired state",
            "A3S Gateway and NGINX start from different problems",
            "Comparison boundary.",
            "One data plane, six capability areas",
            "Measure the model stream, not a request-rate proxy",
            'data-ai-profile="stream-overhead-c1"',
            'data-ai-profile="stream-overhead-c64"',
            'data-ai-profile="stream-paced-c64"',
            'data-ai-profile="prompt-256k"',
            'data-performance-profile="https-http2"',
            'data-performance-profile="websocket-echo"',
            'data-performance-profile="openai-stream"',
            "Production Candidate, with explicit GA gates",
            "data-config-demo",
            'data-config-step="service"',
            "Node API",
            "docs/",
            "https://a3s-lab.github.io/Gateway/install.sh",
            "https://a3s-lab.github.io/Gateway/install.ps1",
        ):
            if marker not in index_html:
                errors.append(f"product story marker is missing: {marker}")

    docs_path = SITE_ROOT / "docs" / "index.html"
    docs_html = page_html.get(docs_path)
    if docs_html is not None:
        for marker in (
            "A3S Gateway documentation",
            'aria-label="A3S Gateway home"',
            '<span>A3S <b>Gateway</b> Docs</span>',
            'id="versioning"',
            "v1.1 stable documentation",
            'id="feature-status"',
            "Feature status and roadmap",
            "Gateway foundation",
            "Current delivery",
            "Planned work and open proof",
            "I0.2b",
            "I0.2c",
            "H0.3-H0.5",
            "Automatic gradual rollout",
            "Native MCP or remote Agent traffic",
            'id="configuration"',
            'id="middleware"',
            'id="custom-middleware"',
            "MiddlewareRegistry",
            "Gateway::with_middlewares",
            "rate-limit-redis",
            "dynamic libraries or Wasm plugins",
            'id="performance"',
            "RATE / P50 / P90 / P99",
            "all ten traffic profiles",
            "A3S Cloud",
            "Current posture: Production Candidate",
            "Enterprise GA",
        ):
            if marker not in docs_html:
                errors.append(f"documentation marker is missing: {marker}")

    for relative_path in ("docs/index.html", "docs/next/index.html"):
        html = page_html.get(SITE_ROOT / relative_path)
        if html is None:
            continue
        for obsolete_brand in ("A3S OS Docs", "A3S OS Gateway home"):
            if obsolete_brand in html:
                errors.append(
                    f"{relative_path} exposes obsolete product branding: "
                    f"{obsolete_brand}"
                )

    for relative_path in ("traffic-profiles.js",):
        script_path = SITE_ROOT / relative_path
        if not script_path.is_file():
            continue
        script = script_path.read_text(encoding="utf-8")
        for profile_id in EXPECTED_TRAFFIC_PROFILES:
            if profile_id not in script:
                errors.append(
                    f"{relative_path} is missing traffic profile {profile_id!r}"
                )

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
    validate_ai_comparison(errors)
    validate_documentation_versions(errors, page_html, page_ids)

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
