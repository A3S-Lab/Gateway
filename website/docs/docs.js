(() => {
  "use strict";

  const links = [...document.querySelectorAll("[data-doc-link]")];
  const sections = links
    .map((link) => document.querySelector(link.getAttribute("href")))
    .filter(Boolean);

  if ("IntersectionObserver" in window && sections.length) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top)[0];
      if (!visible) return;
      links.forEach((link) => {
        const active = link.getAttribute("href") === `#${visible.target.id}`;
        link.classList.toggle("is-active", active);
        if (active) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    }, { rootMargin: "-18% 0px -72%", threshold: 0 });
    sections.forEach((section) => observer.observe(section));
  }

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) throw new Error("copy failed");
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copyTarget);
      if (!target) return;
      const original = button.textContent;
      try {
        await copyText(target.textContent.trim());
        button.textContent = "COPIED";
      } catch {
        button.textContent = "SELECT";
      }
      window.setTimeout(() => { button.textContent = original; }, 1400);
    });
  });

  function formatRate(value, unit) {
    let number;
    if (value >= 1_000_000) number = `${(value / 1_000_000).toFixed(2)}M`;
    else if (value >= 1_000) number = `${(value / 1_000).toFixed(1)}k`;
    else number = value.toFixed(0);
    return `${number} ${unit}`;
  }

  function formatLatency(value) {
    if (value >= 1_000) return `${(value / 1_000).toFixed(2)} ms`;
    return `${value.toFixed(value >= 100 ? 0 : 1)} µs`;
  }

  function appendLocalized(element, english, chinese) {
    const en = document.createElement("span");
    en.className = "lang lang-en";
    en.textContent = english;
    const zh = document.createElement("span");
    zh.className = "lang lang-zh";
    zh.textContent = chinese;
    element.append(en, zh);
  }

  const protocolProfiles = window.A3S_GATEWAY_TRAFFIC_PROFILES || [];

  async function loadProtocolMatrix() {
    const rows = document.querySelector("[data-doc-proxy-rows]");
    if (!rows) return;
    try {
      const response = await fetch("../assets/performance-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`protocol matrix response ${response.status}`);
      const payload = await response.json();
      const published = payload.profiles && typeof payload.profiles === "object"
        ? payload.profiles
        : {
          "http1-small": {
            proxies: payload.proxies,
            comparison: payload.comparison,
          },
        };
      const profiles = protocolProfiles.map((catalog) => ({
        ...catalog,
        ...(published[catalog.id] || {}),
      }));
      rows.replaceChildren();
      profiles.forEach((profile) => {
        const a3s = profile.proxies?.["a3s-gateway"]?.median;
        const nginx = profile.proxies?.nginx?.median;
        const ratios = profile.comparison;
        const a3sRate = a3s?.operations_per_second ?? a3s?.requests_per_second;
        const nginxRate = nginx?.operations_per_second ?? nginx?.requests_per_second;
        const measured = [
          a3sRate,
          nginxRate,
          a3s?.p50_latency_us,
          a3s?.p90_latency_us,
          a3s?.p99_latency_us,
          nginx?.p50_latency_us,
          nginx?.p90_latency_us,
          nginx?.p99_latency_us,
          ratios?.a3s_to_nginx_throughput_ratio,
          ratios?.a3s_to_nginx_p99_latency_ratio,
        ].every(Number.isFinite);
        const row = document.createElement("tr");
        row.dataset.measured = String(measured);

        const traffic = document.createElement("th");
        const label = document.createElement("strong");
        label.textContent = profile.label;
        const workload = document.createElement("small");
        appendLocalized(workload, profile.workload || profile.workloadEn, profile.workloadZh);
        traffic.append(label, workload);

        const load = document.createElement("td");
        appendLocalized(load, profile.concurrencyEn, profile.concurrencyZh);

        const productCell = (metrics, rate) => {
          const cell = document.createElement("td");
          cell.className = "matrix-value";
          if (!measured) {
            appendLocalized(cell, "Pending complete matrix run", "等待完整矩阵实测");
            return cell;
          }
          const strong = document.createElement("strong");
          strong.textContent = formatRate(rate, profile.unit || "ops/s");
          const latency = document.createElement("small");
          latency.textContent = `P50 ${formatLatency(metrics.p50_latency_us)} / P90 ${formatLatency(metrics.p90_latency_us)} / P99 ${formatLatency(metrics.p99_latency_us)}`;
          cell.append(strong, latency);
          return cell;
        };

        const ratio = document.createElement("td");
        ratio.className = "matrix-value";
        if (measured) {
          const strong = document.createElement("strong");
          strong.textContent = `RATE ${ratios.a3s_to_nginx_throughput_ratio.toFixed(2)}×`;
          const latency = document.createElement("small");
          latency.textContent = `P99 ${ratios.a3s_to_nginx_p99_latency_ratio.toFixed(2)}×`;
          ratio.append(strong, latency);
        } else {
          ratio.textContent = "Not measured";
        }

        row.append(
          traffic,
          load,
          productCell(a3s, a3sRate),
          productCell(nginx, nginxRate),
          ratio,
        );
        rows.append(row);
      });
      const run = document.querySelector("[data-doc-proxy-run]");
      if (run && typeof payload.run_url === "string") run.href = payload.run_url;
    } catch (error) {
      console.warn("Protocol matrix data could not be loaded", error);
    }
  }

  void loadProtocolMatrix();
})();
