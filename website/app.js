(() => {
  "use strict";

  const root = document.documentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const storage = {
    get(key) {
      try {
        return window.localStorage.getItem(key);
      } catch {
        return null;
      }
    },
    set(key, value) {
      try {
        window.localStorage.setItem(key, value);
      } catch {
        // The interface remains functional when storage is unavailable.
      }
    },
  };

  const languageButton = document.querySelector("[data-language-toggle]");
  const preferredLanguage = storage.get("a3s-gateway-language");
  const initialLanguage = preferredLanguage === "zh" || preferredLanguage === "en"
    ? preferredLanguage
    : (navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en");

  function setLanguage(language) {
    root.dataset.language = language;
    root.lang = language === "zh" ? "zh-CN" : "en";
    storage.set("a3s-gateway-language", language);
    if (languageButton) {
      languageButton.setAttribute(
        "aria-label",
        language === "zh" ? "Switch site language to English" : "切换网站语言为中文",
      );
    }
  }

  setLanguage(initialLanguage);
  languageButton?.addEventListener("click", () => {
    setLanguage(root.dataset.language === "zh" ? "en" : "zh");
  });

  const menuButton = document.querySelector(".menu-toggle");
  const navigation = document.querySelector("#nav-links");

  function closeMenu({ restoreFocus = false } = {}) {
    if (!menuButton || !navigation) return;
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.setAttribute("aria-label", "Open navigation");
    navigation.classList.remove("is-open");
    if (restoreFocus) menuButton.focus();
  }

  menuButton?.addEventListener("click", () => {
    const open = menuButton.getAttribute("aria-expanded") !== "true";
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    navigation?.classList.toggle("is-open", open);
  });

  navigation?.addEventListener("click", (event) => {
    if (event.target.closest("a")) closeMenu();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && navigation?.classList.contains("is-open")) {
      closeMenu({ restoreFocus: true });
    }
  });

  window.matchMedia("(min-width: 821px)").addEventListener("change", (event) => {
    if (event.matches) closeMenu();
  });

  function wireTabs(buttonSelector, activate) {
    const buttons = [...document.querySelectorAll(buttonSelector)];
    if (!buttons.length) return;

    buttons.forEach((button, index) => {
      button.addEventListener("click", () => activate(button, buttons));
      button.addEventListener("keydown", (event) => {
        let nextIndex;
        if (event.key === "ArrowRight" || event.key === "ArrowDown") {
          nextIndex = (index + 1) % buttons.length;
        } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
          nextIndex = (index - 1 + buttons.length) % buttons.length;
        } else if (event.key === "Home") {
          nextIndex = 0;
        } else if (event.key === "End") {
          nextIndex = buttons.length - 1;
        } else {
          return;
        }
        event.preventDefault();
        activate(buttons[nextIndex], buttons);
        buttons[nextIndex].focus();
      });
    });
  }

  wireTabs(".console-tabs [role='tab']", (activeButton, buttons) => {
    const panelName = activeButton.dataset.panel;
    buttons.forEach((button) => {
      const selected = button === activeButton;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    document.querySelectorAll("[data-console-panel]").forEach((panel) => {
      const active = panel.dataset.consolePanel === panelName;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });
  });

  const installOptions = {
    unix: {
      command: "curl --proto '=https' --tlsv1.2 -LsSf https://a3s-lab.github.io/Gateway/install.sh | sh",
      proof: { en: "platform detection · exact SHA-256 · version check", zh: "平台检测 · 精确 SHA-256 · 版本检查" },
    },
    windows: {
      command: "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; irm https://a3s-lab.github.io/Gateway/install.ps1 | iex",
      proof: { en: "native ZIP · explicit Cargo fallback", zh: "原生 ZIP · 明确的 Cargo 回退" },
    },
    cargo: {
      command: "cargo install a3s-gateway",
      proof: { en: "Rust 1.88+ from crates.io", zh: "通过 crates.io 安装 · Rust 1.88+" },
    },
  };
  const installPanel = document.querySelector("#install-command");
  const installCode = document.querySelector("[data-install-command]");
  const installProofEnglish = document.querySelector(".install-proof .lang-en");
  const installProofChinese = document.querySelector(".install-proof .lang-zh");

  wireTabs(".install-tabs [role='tab']", (activeButton, buttons) => {
    const option = installOptions[activeButton.dataset.install];
    if (!option || !installCode) return;
    buttons.forEach((button) => {
      const selected = button === activeButton;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    installCode.textContent = option.command;
    installPanel?.setAttribute("aria-labelledby", activeButton.id);
    if (installProofEnglish) installProofEnglish.textContent = option.proof.en;
    if (installProofChinese) installProofChinese.textContent = option.proof.zh;
  });

  const copyButton = document.querySelector("[data-copy-install]");

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const input = document.createElement("textarea");
    input.value = text;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.append(input);
    input.select();
    const copied = document.execCommand("copy");
    input.remove();
    if (!copied) throw new Error("Copy command was rejected");
  }

  copyButton?.addEventListener("click", async () => {
    const command = installCode?.textContent?.trim();
    if (!command) return;
    const original = copyButton.textContent;
    try {
      await copyText(command);
      copyButton.textContent = "COPIED";
    } catch {
      copyButton.textContent = "SELECT";
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(installCode);
      selection?.removeAllRanges();
      selection?.addRange(range);
    }
    window.setTimeout(() => {
      copyButton.textContent = original;
    }, 1600);
  });

  function formatBenchmarkDuration(nanoseconds) {
    if (nanoseconds < 1_000) return `${nanoseconds.toFixed(1)} ns`;
    if (nanoseconds < 1_000_000) return `${(nanoseconds / 1_000).toFixed(3)} µs`;
    return `${(nanoseconds / 1_000_000).toFixed(3)} ms`;
  }

  async function loadBenchmarkData() {
    const cards = [...document.querySelectorAll("[data-benchmark-group]")];
    if (!cards.length) return;

    try {
      const response = await fetch("assets/performance-data.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`benchmark response ${response.status}`);
      const payload = await response.json();
      if (!Array.isArray(payload.results)) throw new Error("benchmark results are missing");

      const records = cards.map((card) => {
        const parameter = Number(card.dataset.benchmarkParameter);
        const record = payload.results.find((result) => (
          result.group === card.dataset.benchmarkGroup
          && result.scenario === card.dataset.benchmarkScenario
          && result.parameter === parameter
        ));
        if (!record || !Number.isFinite(record.median_ns)
          || !Number.isFinite(record.ci95_lower_ns)
          || !Number.isFinite(record.ci95_upper_ns)) {
          throw new Error(`benchmark result is missing for ${card.dataset.benchmarkGroup}/${card.dataset.benchmarkScenario}/${parameter}`);
        }
        return [card, record];
      });

      records.forEach(([card, record]) => {
        const value = card.querySelector("[data-benchmark-value]");
        const confidenceInterval = card.querySelector("[data-benchmark-ci]");
        if (value) value.textContent = formatBenchmarkDuration(record.median_ns);
        if (confidenceInterval) {
          confidenceInterval.textContent = `95% CI ${formatBenchmarkDuration(record.ci95_lower_ns)}–${formatBenchmarkDuration(record.ci95_upper_ns)}`;
        }
      });

      const commit = document.querySelector("[data-benchmark-commit]");
      const runner = document.querySelector("[data-benchmark-runner]");
      const cpu = document.querySelector("[data-benchmark-cpu]");
      const run = document.querySelector("[data-benchmark-run]");
      const environment = payload.environment || {};

      if (commit && typeof payload.commit === "string") commit.textContent = payload.commit.slice(0, 8);
      if (runner) {
        const memoryGib = Number.isFinite(environment.memory_mib)
          ? `${(environment.memory_mib / 1024).toFixed(1)} GiB`
          : "memory unavailable";
        runner.textContent = `${environment.runner_image || "GitHub-hosted runner"} · ${environment.logical_cpus || "?"} vCPU · ${memoryGib}`;
        runner.title = runner.textContent;
      }
      if (cpu && environment.cpu_model) {
        cpu.textContent = environment.cpu_model;
        cpu.title = environment.cpu_model;
      }
      if (run && typeof payload.run_url === "string") run.href = payload.run_url;
    } catch (error) {
      // Static values remain visible if the JSON cannot be fetched locally.
      console.warn("Benchmark data could not be refreshed", error);
    }
  }

  void loadBenchmarkData();

  function formatRequestsPerSecond(value) {
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M req/s`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k req/s`;
    return `${value.toFixed(0)} req/s`;
  }

  function formatLatencyMicroseconds(value) {
    if (value >= 1_000) return `${(value / 1_000).toFixed(2)} ms`;
    return `${value.toFixed(value >= 100 ? 0 : 1)} µs`;
  }

  async function loadProxyComparison() {
    const comparison = document.querySelector("[data-proxy-comparison]");
    if (!comparison) return;
    try {
      const response = await fetch("assets/performance-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`proxy comparison response ${response.status}`);
      const payload = await response.json();
      const a3s = payload.proxies?.["a3s-gateway"]?.median;
      const nginx = payload.proxies?.nginx?.median;
      const positions = payload.comparison?.positions;
      if (!a3s || !nginx || !positions) throw new Error("proxy comparison fields are missing");

      const a3sRps = comparison.querySelector("[data-proxy-a3s-rps]");
      const nginxRps = comparison.querySelector("[data-proxy-nginx-rps]");
      const a3sLatency = comparison.querySelector("[data-proxy-a3s-latency]");
      const nginxLatency = comparison.querySelector("[data-proxy-nginx-latency]");
      if (a3sRps) a3sRps.textContent = formatRequestsPerSecond(a3s.requests_per_second);
      if (nginxRps) nginxRps.textContent = formatRequestsPerSecond(nginx.requests_per_second);
      if (a3sLatency) a3sLatency.textContent = `P50 ${formatLatencyMicroseconds(a3s.p50_latency_us)} · P99 ${formatLatencyMicroseconds(a3s.p99_latency_us)}`;
      if (nginxLatency) nginxLatency.textContent = `P50 ${formatLatencyMicroseconds(nginx.p50_latency_us)} · P99 ${formatLatencyMicroseconds(nginx.p99_latency_us)}`;

      const verdict = comparison.querySelector("[data-proxy-verdict]");
      const positionLabel = {
        en: {
          a3s_leads: "A3S leads",
          within_threshold: "within 3%",
          nginx_leads: "NGINX leads",
        },
        zh: {
          a3s_leads: "A3S 指标领先",
          within_threshold: "差异在 3% 内",
          nginx_leads: "NGINX 指标领先",
        },
      };
      if (verdict) {
        verdict.innerHTML = `<span class="lang lang-en">Throughput: ${positionLabel.en[positions.throughput]}; P99 latency: ${positionLabel.en[positions.p99_latency]}</span><span class="lang lang-zh">吞吐：${positionLabel.zh[positions.throughput]}；P99 延迟：${positionLabel.zh[positions.p99_latency]}</span>`;
      }

      const summary = document.querySelector("[data-proxy-comparison-summary] strong");
      if (summary) {
        summary.innerHTML = `<span class="lang lang-en">Same-host result — throughput: ${positionLabel.en[positions.throughput]}; P99 latency: ${positionLabel.en[positions.p99_latency]}</span><span class="lang lang-zh">同机结果——吞吐：${positionLabel.zh[positions.throughput]}；P99 延迟：${positionLabel.zh[positions.p99_latency]}</span>`;
      }
    } catch (error) {
      console.warn("Proxy comparison data could not be loaded", error);
    }
  }

  void loadProxyComparison();

  const configDemo = document.querySelector("[data-config-demo]");
  const configButtons = [...document.querySelectorAll("[data-config-step]")];
  let configTimer = 0;

  function configCyclePaused() {
    return reducedMotion.matches
      || document.hidden
      || configDemo?.matches(":hover")
      || configDemo?.contains(document.activeElement);
  }

  function scheduleConfigCycle() {
    window.clearTimeout(configTimer);
    configButtons.forEach((button) => button.classList.remove("is-cycling"));
    if (!configDemo || !configButtons.length || configCyclePaused()) return;

    const activeButton = configButtons.find((button) => button.getAttribute("aria-selected") === "true")
      || configButtons[0];
    // Restart the progress indicator whenever automatic playback resumes.
    void activeButton.offsetWidth;
    activeButton.classList.add("is-cycling");
    configTimer = window.setTimeout(() => {
      const activeIndex = configButtons.indexOf(activeButton);
      activateConfigStep(configButtons[(activeIndex + 1) % configButtons.length], configButtons);
    }, 4_800);
  }

  function activateConfigStep(activeButton, buttons) {
    const step = activeButton.dataset.configStep;
    buttons.forEach((button) => {
      const selected = button === activeButton;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    document.querySelectorAll("[data-config-block]").forEach((block) => {
      block.classList.toggle("is-active", block.dataset.configBlock === step);
    });
    document.querySelectorAll("[data-config-note]").forEach((note) => {
      note.hidden = note.dataset.configNote !== step;
    });
    if (configDemo) configDemo.dataset.activeStep = step;
    scheduleConfigCycle();
  }

  wireTabs("[data-config-step]", activateConfigStep);
  configDemo?.addEventListener("mouseenter", scheduleConfigCycle);
  configDemo?.addEventListener("mouseleave", scheduleConfigCycle);
  configDemo?.addEventListener("focusin", scheduleConfigCycle);
  configDemo?.addEventListener("focusout", () => window.setTimeout(scheduleConfigCycle));
  document.addEventListener("visibilitychange", scheduleConfigCycle);
  reducedMotion.addEventListener("change", scheduleConfigCycle);
  scheduleConfigCycle();

  const revealItems = document.querySelectorAll(".reveal");
  if (reducedMotion.matches || !("IntersectionObserver" in window)) {
    revealItems.forEach((item) => item.classList.add("is-visible"));
  } else {
    const observer = new IntersectionObserver((entries, revealObserver) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -8%", threshold: 0.08 });
    revealItems.forEach((item) => observer.observe(item));
  }

  document.querySelectorAll("[data-current-year]").forEach((node) => {
    node.textContent = String(new Date().getFullYear());
  });

  const canvas = document.querySelector("#route-canvas");
  const context = canvas?.getContext("2d");
  if (!canvas || !context) return;

  let width = 0;
  let height = 0;
  let frame = 0;
  let animationId = 0;

  function resizeCanvas() {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function drawRoute(offset, y, color) {
    const start = -100;
    const end = width + 100;
    context.beginPath();
    context.moveTo(start, y);
    context.bezierCurveTo(width * 0.28, y - 90, width * 0.64, y + 90, end, y - 24);
    context.setLineDash([2, 15]);
    context.lineDashOffset = -offset;
    context.strokeStyle = color;
    context.lineWidth = 1;
    context.stroke();
  }

  function draw() {
    context.clearRect(0, 0, width, height);
    drawRoute(frame * 0.22, height * 0.28, "rgba(87, 148, 255, 0.22)");
    drawRoute(-frame * 0.16, height * 0.72, "rgba(84, 221, 161, 0.15)");
    context.setLineDash([]);
    frame += 1;
    if (!reducedMotion.matches && !document.hidden) {
      animationId = window.requestAnimationFrame(draw);
    }
  }

  function restartCanvas() {
    window.cancelAnimationFrame(animationId);
    resizeCanvas();
    draw();
  }

  window.addEventListener("resize", restartCanvas, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) restartCanvas();
  });
  reducedMotion.addEventListener("change", restartCanvas);
  restartCanvas();
})();
