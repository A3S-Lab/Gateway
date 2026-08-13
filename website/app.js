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
        language === "zh" ? "Switch site language to English" : "Switch site language to Simplified Chinese",
      );
      languageButton.setAttribute(
        "title",
        language === "zh" ? "English" : "简体中文",
      );
    }
  }

  setLanguage(initialLanguage);
  languageButton?.addEventListener("click", () => {
    setLanguage(root.dataset.language === "zh" ? "en" : "zh");
  });

  const menuButton = document.querySelector(".menu-toggle");
  const navigation = document.querySelector("#nav-links");
  const navDropdowns = [...document.querySelectorAll("[data-nav-dropdown]")];

  function closeDropdowns({ except = null, restoreFocus = false } = {}) {
    navDropdowns.forEach((dropdown) => {
      if (dropdown === except || !dropdown.open) return;
      dropdown.open = false;
      if (restoreFocus) dropdown.querySelector("summary")?.focus();
    });
  }

  navDropdowns.forEach((dropdown) => {
    dropdown.addEventListener("toggle", () => {
      if (dropdown.open) closeDropdowns({ except: dropdown });
    });
  });

  function closeMenu({ restoreFocus = false } = {}) {
    if (!menuButton || !navigation) return;
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.setAttribute("aria-label", "Open navigation");
    navigation.classList.remove("is-open");
    closeDropdowns();
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

  document.querySelector(".site-header")?.addEventListener("click", (event) => {
    if (event.target.closest("a")) closeDropdowns();
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-nav-dropdown]")) closeDropdowns();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const openDropdown = navDropdowns.find((dropdown) => dropdown.open);
    if (openDropdown) {
      closeDropdowns({ restoreFocus: true });
      return;
    }
    if (navigation?.classList.contains("is-open")) closeMenu({ restoreFocus: true });
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
      proof: { en: "platform detection / exact SHA-256 / version check", zh: "平台检测 / 精确 SHA-256 / 版本检查" },
    },
    windows: {
      command: "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; irm https://a3s-lab.github.io/Gateway/install.ps1 | iex",
      proof: { en: "native ZIP / explicit Cargo fallback", zh: "原生 ZIP / 明确的 Cargo 回退" },
    },
    cargo: {
      command: "cargo install a3s-gateway",
      proof: { en: "Rust 1.88+ from crates.io", zh: "通过 crates.io 安装 / Rust 1.88+" },
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
          confidenceInterval.textContent = `95% CI ${formatBenchmarkDuration(record.ci95_lower_ns)}-${formatBenchmarkDuration(record.ci95_upper_ns)}`;
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
        runner.textContent = `${environment.runner_image || "GitHub-hosted runner"} / ${environment.logical_cpus || "?"} vCPU / ${memoryGib}`;
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

  function formatOperationsPerSecond(value, unit) {
    let formatted;
    if (value >= 1_000_000) formatted = `${(value / 1_000_000).toFixed(2)}M`;
    else if (value >= 1_000) formatted = `${(value / 1_000).toFixed(1)}k`;
    else formatted = value.toFixed(0);
    return `${formatted} ${unit}`;
  }

  function formatLatencyMicroseconds(value) {
    if (value >= 1_000) return `${(value / 1_000).toFixed(2)} ms`;
    return `${value.toFixed(value >= 100 ? 0 : 1)} µs`;
  }

  const proxyProfileCatalog = window.A3S_GATEWAY_TRAFFIC_PROFILES || [];

  function appendLocalized(element, english, chinese) {
    const en = document.createElement("span");
    en.className = "lang lang-en";
    en.textContent = english;
    const zh = document.createElement("span");
    zh.className = "lang lang-zh";
    zh.textContent = chinese;
    element.append(en, zh);
  }

  function updateText(selector, value) {
    const element = document.querySelector(selector);
    if (element && value) element.textContent = value;
  }

  function updateLocalizedText(selector, english, chinese) {
    const element = document.querySelector(selector);
    if (!element) return;
    element.replaceChildren();
    appendLocalized(element, english, chinese);
  }

  function formatSuccessRate(value) {
    if (!Number.isFinite(value)) return "Not measured";
    return `${(value * 100).toFixed(value < 0.9995 ? 2 : 1)}%`;
  }

  function formatAiLatency(microseconds) {
    return `${(microseconds / 1_000).toFixed(3)} ms`;
  }

  async function loadAiPerformance() {
    const section = document.querySelector("[data-ai-performance]");
    const rows = section ? [...section.querySelectorAll("[data-ai-profile]")] : [];
    if (!section || !rows.length) return;

    try {
      const response = await fetch("assets/ai-gateway-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`AI performance response ${response.status}`);
      const payload = await response.json();
      const profiles = payload.profiles;
      if (!profiles || typeof profiles !== "object") {
        throw new Error("AI performance profiles are missing");
      }

      rows.forEach((row) => {
        const profile = profiles[row.dataset.aiProfile];
        const a3s = profile?.products?.["a3s-gateway"]?.median;
        const nginx = profile?.products?.nginx?.median;
        const ratios = profile?.comparison;
        const values = [
          a3s?.ttft?.p50_us,
          a3s?.inter_token_latency?.p99_us,
          nginx?.ttft?.p50_us,
          nginx?.inter_token_latency?.p99_us,
          ratios?.a3s_to_nginx_ttft_p50_ratio,
          ratios?.a3s_to_nginx_inter_token_latency_p99_ratio,
          ratios?.a3s_to_nginx_token_goodput_ratio,
        ];
        if (!values.every(Number.isFinite)) {
          throw new Error(`AI profile ${row.dataset.aiProfile} is incomplete`);
        }

        const setRowText = (selector, value) => {
          const element = row.querySelector(selector);
          if (element) element.textContent = value;
        };
        setRowText("[data-ai-a3s-ttft]", `TTFT ${formatAiLatency(a3s.ttft.p50_us)}`);
        setRowText("[data-ai-a3s-itl]", `ITL P99 ${formatAiLatency(a3s.inter_token_latency.p99_us)}`);
        setRowText("[data-ai-nginx-ttft]", `TTFT ${formatAiLatency(nginx.ttft.p50_us)}`);
        setRowText("[data-ai-nginx-itl]", `ITL P99 ${formatAiLatency(nginx.inter_token_latency.p99_us)}`);
        setRowText(
          "[data-ai-ratios]",
          `TTFT ${ratios.a3s_to_nginx_ttft_p50_ratio.toFixed(2)}× · ITL ${ratios.a3s_to_nginx_inter_token_latency_p99_ratio.toFixed(2)}×`,
        );
        setRowText(
          "[data-ai-goodput]",
          `Token goodput ${ratios.a3s_to_nginx_token_goodput_ratio.toFixed(2)}×`,
        );
      });

      const profileCount = Object.keys(profiles).length;
      const trials = payload.methodology?.trials;
      if (!Number.isInteger(trials) || trials < 1) {
        throw new Error("AI trial count is invalid");
      }
      updateText("[data-ai-profile-count]", `${profileCount} workloads`);
      updateText("[data-ai-trial-plan]", `${trials} × alternating`);
      updateText("[data-ai-raw-trials]", `${profileCount * trials * 2} product trials`);
      updateText("[data-ai-correctness]", "100% exact");

      const commit = typeof payload.commit === "string" ? payload.commit.slice(0, 8) : "unknown";
      const cpu = payload.environment?.cpu_model || "runner CPU unavailable";
      const logicalCpus = payload.environment?.logical_cpus || "?";
      const rawTrials = profileCount * trials * 2;
      updateLocalizedText(
        "[data-ai-provenance]",
        `Commit ${commit} / ${logicalCpus} vCPU ${cpu} / ${rawTrials} successful raw trials / synthetic regression evidence, not a capacity forecast.`,
        `提交 ${commit} / ${logicalCpus} vCPU ${cpu} / ${rawTrials} 次原始试验全部成功 / 合成回归证据，不代表容量预测。`,
      );
      const run = section.querySelector("[data-ai-run]");
      if (run && typeof payload.run_url === "string") run.href = payload.run_url;
    } catch (error) {
      // Audited static values remain visible when Pages JSON is unavailable locally.
      console.warn("AI performance data could not be refreshed", error);
    }
  }

  void loadAiPerformance();

  function comparisonPosition(profile) {
    if (profile.capability_alignment === "a3s_feature_enabled_vs_nginx_transport") {
      return { en: "FEATURE-COST ROW", zh: "功能成本场景", value: "neutral" };
    }
    const positions = profile.comparison?.positions || {};
    const a3sRate = ["a3s_higher", "a3s_leads"].includes(positions.throughput);
    const a3sP99 = ["a3s_lower", "a3s_leads"].includes(positions.p99_latency);
    const nginxRate = ["nginx_higher", "nginx_leads"].includes(positions.throughput);
    const nginxP99 = ["nginx_lower", "nginx_leads"].includes(positions.p99_latency);
    if (a3sRate && a3sP99) {
      return { en: "A3S RATE + P99 LEAD", zh: "A3S 吞吐与 P99 更优", value: "a3s" };
    }
    if (nginxRate && nginxP99) {
      return { en: "NGINX RATE + P99 LEAD", zh: "NGINX 吞吐与 P99 更优", value: "nginx" };
    }
    return { en: "MIXED / WITHIN 3%", zh: "结果混合 / 差异小于 3%", value: "neutral" };
  }

  async function loadProxyComparison() {
    const comparison = document.querySelector("[data-proxy-comparison]");
    if (!comparison) return;
    try {
      const response = await fetch("assets/performance-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`proxy comparison response ${response.status}`);
      const payload = await response.json();
      const publishedProfiles = payload.profiles && typeof payload.profiles === "object"
        ? { ...payload.profiles }
        : {
          "http1-small": {
            label: "HTTP/1.1",
            unit: "requests/s",
            workload: "GET, keep-alive, 42-byte JSON response",
            capability_alignment: "equivalent",
            proxies: payload.proxies,
            comparison: payload.comparison,
          },
        };
      const profiles = proxyProfileCatalog.map((catalog) => [
        catalog.id,
        { ...catalog, ...(publishedProfiles[catalog.id] || {}) },
      ]);
      Object.entries(publishedProfiles).forEach(([profileId, profile]) => {
        if (!proxyProfileCatalog.some((catalog) => catalog.id === profileId)) {
          profiles.push([profileId, { id: profileId, ...profile }]);
        }
      });

      const rows = comparison.querySelector("[data-proxy-profile-rows]");
      if (!rows) throw new Error("proxy comparison table is missing");
      rows.replaceChildren();

      let measuredProfiles = 0;

      profiles.forEach(([profileId, profile]) => {
        const a3s = profile.proxies?.["a3s-gateway"]?.median;
        const nginx = profile.proxies?.nginx?.median;
        const ratios = profile.comparison;
        const a3sRate = a3s?.operations_per_second ?? a3s?.requests_per_second;
        const nginxRate = nginx?.operations_per_second ?? nginx?.requests_per_second;
        const measured = [
          a3sRate,
          nginxRate,
          a3s?.average_latency_us,
          a3s?.p50_latency_us,
          a3s?.p90_latency_us,
          a3s?.p99_latency_us,
          nginx?.average_latency_us,
          nginx?.p50_latency_us,
          nginx?.p90_latency_us,
          nginx?.p99_latency_us,
          ratios?.a3s_to_nginx_throughput_ratio,
          ratios?.a3s_to_nginx_p50_latency_ratio,
          ratios?.a3s_to_nginx_p90_latency_ratio,
          ratios?.a3s_to_nginx_p99_latency_ratio,
        ].every(Number.isFinite);
        if (measured) measuredProfiles += 1;

        const row = document.createElement("tr");
        row.dataset.profile = profileId;
        row.dataset.measured = String(measured);
        const traffic = document.createElement("th");
        traffic.scope = "row";
        const label = document.createElement("strong");
        label.textContent = profile.label || profileId;
        const workload = document.createElement("small");
        appendLocalized(
          workload,
          profile.workload || profile.workloadEn || "Workload metadata unavailable",
          profile.workloadZh || profile.workload || "暂无负载说明",
        );
        traffic.append(label, workload);
        if (profile.capability_alignment === "a3s_feature_enabled_vs_nginx_transport") {
          const alignment = document.createElement("em");
          appendLocalized(alignment, "FEATURE COST", "功能成本");
          traffic.append(alignment);
        }

        const load = document.createElement("td");
        load.className = "traffic-load";
        const concurrency = document.createElement("strong");
        appendLocalized(
          concurrency,
          profile.concurrencyEn || "Published run configuration",
          profile.concurrencyZh || "已发布测试配置",
        );
        const generator = document.createElement("small");
        generator.textContent = `${profile.load_generator || profile.generator || "load generator"} / ${profile.unit || "ops/s"}`;
        const operation = document.createElement("small");
        appendLocalized(operation, "Median completed operations", "已完成操作的中位数");
        load.append(concurrency, generator, operation);

        const productCell = (metrics, rate) => {
          const cell = document.createElement("td");
          if (!measured) {
            const pending = document.createElement("span");
            pending.className = "traffic-pending";
            appendLocalized(
              pending,
              "Awaiting the next complete matrix run",
              "等待下一次完整矩阵实测",
            );
            cell.append(pending);
            return cell;
          }
          const throughput = document.createElement("strong");
          throughput.textContent = formatOperationsPerSecond(rate, profile.unit || "ops/s");
          const metricsList = document.createElement("dl");
          metricsList.className = "traffic-metrics";
          [
            ["SUCCESS", formatSuccessRate(metrics.success_rate)],
            ["AVERAGE", formatLatencyMicroseconds(metrics.average_latency_us)],
            ["P50", formatLatencyMicroseconds(metrics.p50_latency_us)],
            ["P90", formatLatencyMicroseconds(metrics.p90_latency_us)],
            ["P99", formatLatencyMicroseconds(metrics.p99_latency_us)],
          ].forEach(([name, value]) => {
            const term = document.createElement("dt");
            term.textContent = name;
            const detail = document.createElement("dd");
            detail.textContent = value;
            metricsList.append(term, detail);
          });
          cell.append(throughput, metricsList);
          return cell;
        };

        const ratioCell = document.createElement("td");
        if (measured) {
          const ratioList = document.createElement("dl");
          ratioList.className = "traffic-ratios";
          [
            ["RATE", ratios.a3s_to_nginx_throughput_ratio],
            ["P50", ratios.a3s_to_nginx_p50_latency_ratio],
            ["P90", ratios.a3s_to_nginx_p90_latency_ratio],
            ["P99", ratios.a3s_to_nginx_p99_latency_ratio],
          ].forEach(([name, value]) => {
            const term = document.createElement("dt");
            term.textContent = name;
            const detail = document.createElement("dd");
            detail.textContent = `${value.toFixed(2)}×`;
            ratioList.append(term, detail);
          });
          const guidance = document.createElement("small");
          appendLocalized(guidance, "Rate: higher / latency: lower", "吞吐越高越好 / 延迟越低越好");
          const position = comparisonPosition(profile);
          const badge = document.createElement("span");
          badge.className = "traffic-position";
          badge.dataset.position = position.value;
          appendLocalized(badge, position.en, position.zh);
          ratioCell.append(ratioList, guidance, badge);
        } else {
          const pending = document.createElement("span");
          pending.className = "traffic-pending";
          appendLocalized(pending, "No measured ratio published", "尚未发布实测比值");
          ratioCell.append(pending);
        }
        row.append(
          traffic,
          load,
          productCell(a3s, a3sRate),
          productCell(nginx, nginxRate),
          ratioCell,
        );
        rows.append(row);
      });

      const summary = document.querySelector("[data-proxy-comparison-summary] strong");
      if (summary) {
        const trialCount = payload.methodology?.trials || "?";
        const english = document.createElement("span");
        english.className = "lang lang-en";
        english.textContent = measuredProfiles === profiles.length
          ? `${measuredProfiles}/${profiles.length} traffic profiles / median of ${trialCount} alternating trials`
          : `${measuredProfiles}/${profiles.length} traffic profiles have published measurements / complete matrix pending`;
        const chinese = document.createElement("span");
        chinese.className = "lang lang-zh";
        chinese.textContent = measuredProfiles === profiles.length
          ? `${measuredProfiles}/${profiles.length} 类流量 / ${trialCount} 轮交替测试的中位数`
          : `${measuredProfiles}/${profiles.length} 类流量已有实测数据 / 完整矩阵待发布`;
        summary.replaceChildren(english, chinese);
      }

      const methodology = payload.methodology || {};
      const duration = methodology.duration_seconds_per_trial;
      const trialCount = methodology.trials;
      if (Number.isFinite(trialCount) && Number.isFinite(duration)) {
        updateText("[data-proxy-trial-plan]", `${trialCount} × ${duration} s`);
      }
      const warmup = methodology.warmup_seconds;
      if (Number.isFinite(warmup)) {
        updateLocalizedText(
          "[data-proxy-warmup]",
          `${warmup} s warm-up / alternating product order`,
          `预热 ${warmup} 秒 / 产品顺序交替`,
        );
      } else {
        updateLocalizedText(
          "[data-proxy-warmup]",
          "Legacy artifact / warm-up metadata unavailable",
          "旧版数据 / 未记录预热信息",
        );
      }
      if (Number.isFinite(methodology.connections)) {
        updateLocalizedText(
          "[data-proxy-concurrency]",
          `${methodology.connections} concurrent operations`,
          `${methodology.connections} 个并发操作`,
        );
      }
      const http2 = methodology.http2_concurrency;
      if (Number.isFinite(http2?.connections) && Number.isFinite(http2?.parallel_streams_per_connection)) {
        updateLocalizedText(
          "[data-proxy-http2-concurrency]",
          `HTTP/2 + gRPC / ${http2.connections} connections × ${http2.parallel_streams_per_connection} streams`,
          `HTTP/2 + gRPC / ${http2.connections} 个连接 × ${http2.parallel_streams_per_connection} 条流`,
        );
      } else {
        updateLocalizedText(
          "[data-proxy-http2-concurrency]",
          "Complete matrix plan / HTTP/2 and gRPC use 4 × 16 streams",
          "完整矩阵计划 / HTTP/2 与 gRPC 使用 4 × 16 条流",
        );
      }

      const environment = payload.environment || {};
      const memory = Number.isFinite(environment.memory_mib)
        ? `${(environment.memory_mib / 1024).toFixed(1)} GiB`
        : "unknown memory";
      updateText(
        "[data-proxy-runner]",
        `${environment.runner_image || "GitHub-hosted"} / ${environment.logical_cpus || "?"} vCPU`,
      );
      updateText(
        "[data-proxy-environment]",
        `${environment.cpu_model || "Shared runner CPU"} / ${memory}`,
      );
      updateText("[data-proxy-a3s-version]", payload.versions?.a3s_gateway || "A3S Gateway release");
      updateText("[data-proxy-nginx-version]", payload.versions?.nginx || "NGINX package baseline");

      const provenance = document.querySelector("[data-proxy-provenance]");
      if (provenance) {
        provenance.replaceChildren();
        const commit = typeof payload.commit === "string" ? payload.commit.slice(0, 8) : "unknown";
        const generatedAt = typeof payload.generated_at === "string" ? payload.generated_at : "unknown time";
        appendLocalized(
          provenance,
          `Commit ${commit} / generated ${generatedAt} / synthetic same-host results on shared infrastructure, not a capacity forecast.`,
          `提交 ${commit} / 生成于 ${generatedAt} / 共享基础设施上的同机合成结果，不代表容量预测。`,
        );
      }
      const run = document.querySelector("[data-proxy-run]");
      if (run && typeof payload.run_url === "string") run.href = payload.run_url;
    } catch (error) {
      console.warn("Proxy comparison data could not be loaded", error);
    }
  }

  void loadProxyComparison();

  function describePerformanceRatio(ratio, metric, language) {
    const difference = Math.round(Math.abs(ratio - 1) * 100);
    if (difference <= 3) {
      return language === "zh" ? "差异小于 3%" : "within 3%";
    }

    if (metric === "throughput") {
      if (ratio > 1) return language === "zh" ? `吞吐高 ${difference}%` : `${difference}% higher throughput`;
      return language === "zh" ? `吞吐低 ${difference}%` : `${difference}% lower throughput`;
    }

    if (ratio < 1) return language === "zh" ? `P99 低 ${difference}%` : `${difference}% lower P99`;
    return language === "zh" ? `P99 高 ${difference}%` : `${difference}% higher P99`;
  }

  async function loadPerformanceHighlights() {
    const section = document.querySelector("[data-performance-comparison]");
    if (!section) return;

    try {
      const response = await fetch("assets/performance-comparison.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`performance comparison response ${response.status}`);
      const payload = await response.json();
      const profiles = payload.profiles;
      if (!profiles || typeof profiles !== "object") throw new Error("performance profiles are missing");

      section.querySelectorAll("[data-performance-profile]").forEach((row) => {
        const profile = profiles[row.dataset.performanceProfile];
        const a3s = profile?.proxies?.["a3s-gateway"]?.median;
        const nginx = profile?.proxies?.nginx?.median;
        const ratios = profile?.comparison;
        const a3sRate = a3s?.operations_per_second ?? a3s?.requests_per_second;
        const nginxRate = nginx?.operations_per_second ?? nginx?.requests_per_second;
        if (![a3sRate, nginxRate, a3s?.p99_latency_us, nginx?.p99_latency_us,
          ratios?.a3s_to_nginx_throughput_ratio, ratios?.a3s_to_nginx_p99_latency_ratio]
          .every(Number.isFinite)) return;

        const setRowText = (selector, value) => {
          const element = row.querySelector(selector);
          if (element) element.textContent = value;
        };

        setRowText("[data-performance-a3s-rate]", formatOperationsPerSecond(a3sRate, profile.unit));
        setRowText("[data-performance-nginx-rate]", formatOperationsPerSecond(nginxRate, profile.unit));
        setRowText("[data-performance-a3s-p99]", `P99 ${formatLatencyMicroseconds(a3s.p99_latency_us)}`);
        setRowText("[data-performance-nginx-p99]", `P99 ${formatLatencyMicroseconds(nginx.p99_latency_us)}`);

        const english = [
          describePerformanceRatio(ratios.a3s_to_nginx_throughput_ratio, "throughput", "en"),
          describePerformanceRatio(ratios.a3s_to_nginx_p99_latency_ratio, "p99", "en"),
        ].join(" / ");
        const chinese = [
          describePerformanceRatio(ratios.a3s_to_nginx_throughput_ratio, "throughput", "zh"),
          describePerformanceRatio(ratios.a3s_to_nginx_p99_latency_ratio, "p99", "zh"),
        ].join(" / ");
        const outcome = row.querySelector("[data-performance-outcome]");
        if (outcome) {
          const featureCost = profile.capability_alignment === "a3s_feature_enabled_vs_nginx_transport";
          outcome.replaceChildren();
          appendLocalized(
            outcome,
            featureCost ? `A3S validation: ${english}` : english,
            featureCost ? `A3S 校验成本：${chinese}` : chinese,
          );
        }

        const a3sLeads = ratios.a3s_to_nginx_throughput_ratio > 1.03
          && ratios.a3s_to_nginx_p99_latency_ratio < 0.97;
        row.dataset.profileStatus = profile.capability_alignment === "a3s_feature_enabled_vs_nginx_transport"
          ? "feature"
          : (a3sLeads ? "lead" : "mixed");
      });

      const methodology = payload.methodology || {};
      if (Number.isFinite(methodology.trials) && Number.isFinite(methodology.duration_seconds_per_trial)) {
        updateText("[data-performance-plan]", `${methodology.trials} × ${methodology.duration_seconds_per_trial} s`);
      }
      if (Number.isFinite(methodology.connections)) {
        updateLocalizedText(
          "[data-performance-load]",
          `${methodology.connections} operations`,
          `${methodology.connections} 个并发操作`,
        );
      }
      const http2 = methodology.http2_concurrency;
      if (Number.isFinite(http2?.connections) && Number.isFinite(http2?.parallel_streams_per_connection)) {
        updateText("[data-performance-http2]", `${http2.connections} × ${http2.parallel_streams_per_connection} streams`);
      }

      const environment = payload.environment || {};
      const cpu = typeof environment.cpu_model === "string"
        ? (environment.cpu_model.match(/EPYC\s+[A-Z0-9]+/i)?.[0] || environment.cpu_model)
        : "shared runner";
      updateText("[data-performance-runner]", `${environment.logical_cpus || "?"} vCPU / ${cpu}`);

      const provenance = section.querySelector("[data-performance-provenance]");
      if (provenance) {
        const commit = typeof payload.commit === "string" ? payload.commit.slice(0, 8) : "unknown";
        const date = typeof payload.generated_at === "string" ? payload.generated_at.slice(0, 10) : "unknown date";
        provenance.replaceChildren();
        appendLocalized(
          provenance,
          `Commit ${commit} / published ${date} / shared infrastructure / regression evidence, not a capacity forecast.`,
          `提交 ${commit} / 发布于 ${date} / 共享基础设施 / 用于回归判断，不代表容量预测。`,
        );
      }
      const run = section.querySelector("[data-performance-run]");
      if (run && typeof payload.run_url === "string") run.href = payload.run_url;
    } catch (error) {
      // Published fallback values remain readable when local JSON loading is unavailable.
      console.warn("Performance highlights could not be refreshed", error);
    }
  }

  void loadPerformanceHighlights();

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
