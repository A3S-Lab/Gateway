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
      proof: { en: "platform detection · SHA-256 required", zh: "平台检测 · 强制 SHA-256 校验" },
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
