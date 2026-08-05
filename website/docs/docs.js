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

  async function loadProtocolMatrix() {
    const rows = document.querySelector("[data-doc-proxy-rows]");
    if (!rows) return;
    try {
      const response = await fetch("../assets/performance-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`protocol matrix response ${response.status}`);
      const payload = await response.json();
      const profiles = payload.profiles && typeof payload.profiles === "object"
        ? Object.values(payload.profiles)
        : [{
          label: "HTTP/1.1",
          unit: "requests/s",
          proxies: payload.proxies,
          comparison: payload.comparison,
        }];
      rows.replaceChildren();
      profiles.forEach((profile) => {
        const a3s = profile.proxies?.["a3s-gateway"]?.median;
        const nginx = profile.proxies?.nginx?.median;
        const ratios = profile.comparison;
        const a3sRate = a3s?.operations_per_second ?? a3s?.requests_per_second;
        const nginxRate = nginx?.operations_per_second ?? nginx?.requests_per_second;
        if (!Number.isFinite(a3sRate) || !Number.isFinite(nginxRate)
          || !Number.isFinite(ratios?.a3s_to_nginx_throughput_ratio)
          || !Number.isFinite(ratios?.a3s_to_nginx_p99_latency_ratio)) {
          throw new Error("protocol matrix fields are missing");
        }
        const row = document.createElement("tr");
        [
          profile.label,
          formatRate(a3sRate, profile.unit || "ops/s"),
          formatRate(nginxRate, profile.unit || "ops/s"),
          `${(ratios.a3s_to_nginx_throughput_ratio * 100).toFixed(1)}%`,
          `${ratios.a3s_to_nginx_p99_latency_ratio.toFixed(2)}×`,
        ].forEach((value, index) => {
          const cell = document.createElement(index === 0 ? "th" : "td");
          cell.textContent = value;
          row.append(cell);
        });
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
