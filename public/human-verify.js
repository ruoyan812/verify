/**
 * HumanVerify —— Human verification widget by Worker
 *
 * Use script:
 *
 *   <button data-human-verify data-callback="onVerified" data-input="#token">点击验证</button>
 *   <script src="https://verify.roooooyan.work/human-verify.js" async></script>
 *   <script>
 *     function onVerified(token, btn, risk) {
 *       console.log(token, risk);
 *     }
 *   </script>
 *
 * Coding sript avalible: 
 *   HumanVerify.render("#myBtn", { onVerified: (token, btn, risk) => {...} });
 *   const token = await HumanVerify.verify();   
 *   HumanVerify.lastRisk;                       
 *
 * After successful verification, the following will be done: write btn.dataset.token, and fill the token into the hidden field specified in data-input.
 * Calls the global data-callback function or the onVerified callback (the third parameter is the risk assessment). The token is valid only once.
 */
(function () {
  const API_BASE = (() => {
    try {
      const s = document.currentScript;
      if (s && s.src) return new URL(s.src).origin;
    } catch (e) {}
    return location.origin;
  })();

  let lastRisk = null;

  const POW_SRC = `
self.onmessage = async (e) => {
  const challenge = e.data.challenge;
  const signalsHash = e.data.signalsHash;
  const difficulty = e.data.difficulty;
  const enc = (s) => new TextEncoder().encode(s);
  const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  function lead(h) {
    let bits = 0;
    for (const c of h) {
      const v = parseInt(c, 16);
      if (v === 0) bits += 4;
      else { bits += Math.clz32(v) - 28; break; }
    }
    return bits;
  }
  let n = 0;
  const MAX = 80000000;
  while (n < MAX) {
    const h = hex(await crypto.subtle.digest("SHA-256", enc(challenge + "|" + signalsHash + "|" + n)));
    if (lead(h) >= difficulty) { self.postMessage({ nonce: String(n) }); return; }
    n++;
  }
  self.postMessage({ nonce: null });
};
`;

  function makeWorker() {
    const blob = new Blob([POW_SRC], { type: "application/javascript" });
    return new Worker(URL.createObjectURL(blob));
  }

  if (typeof window !== "undefined") {
    window.addEventListener("mousemove", () => (window.__hv_m = (window.__hv_m || 0) + 1), { passive: true });
    window.addEventListener("scroll", () => (window.__hv_s = (window.__hv_s || 0) + 1), { passive: true });
    window.addEventListener("keydown", () => (window.__hv_k = (window.__hv_k || 0) + 1), { passive: true });
  }

  function getPlugins() {
    try {
      const plugins = [];
      const ps = navigator.plugins;
      if (ps) for (let i = 0; i < ps.length; i++) plugins.push(ps[i].name);
      const mimeTypes = [];
      const mts = navigator.mimeTypes;
      if (mts) for (let i = 0; i < mts.length; i++) mimeTypes.push(mts[i].type);
      return { plugins, mimeTypes };
    } catch {
      return { plugins: [], mimeTypes: [] };
    }
  }

  function detectAutomation() {
    const flags = [];
    let score = 0;
    const nav = navigator;
    const ua = nav.userAgent || "";

    if (nav.webdriver === true) {
      score += 45;
      flags.push("webdriver");
    }

    let cdc = false;
    try {
      cdc = Object.getOwnPropertyNames(window).some(
        (k) => k.indexOf("cdc_") === 0 || k.indexOf("$cdc_") === 0,
      );
    } catch {}
    if (cdc) {
      score += 45;
      flags.push("chromedriver-cdc");
    }

    if (/headless|phantomjs|selenium|webdriver|playwright|puppeteer|scrapy|curl|wget|python-requests|go-http/i.test(ua)) {
      score += 35;
      flags.push("bot-ua");
    }

    if (/headless/i.test(ua) && !window.chrome) {
      score += 25;
      flags.push("headless-no-chrome");
    }

    if (window.__nightmare || typeof window.callPhantom !== "undefined") {
      score += 40;
      flags.push("phantom");
    }

    if (window.outerWidth === 0 && window.outerHeight === 0) {
      score += 15;
      flags.push("zero-viewport");
    }

    if (nav.hardwareConcurrency === 0) {
      score += 10;
      flags.push("zero-cores");
    }

    if (nav.platform) {
      if (/win/i.test(nav.platform) && !/windows/i.test(ua)) {
        score += 10;
        flags.push("platform-mismatch");
      }
      if (/mac/i.test(nav.platform) && !/mac/i.test(ua)) {
        score += 10;
        flags.push("platform-mismatch");
      }
    }

    return { score: Math.min(100, score), flags };
  }

  async function collectSignals() {
    const nav = navigator;
    const plug = getPlugins();
    const sig = {
      ua: nav.userAgent,
      lang: nav.language,
      langs: nav.languages ? nav.languages.join(",") : "",
      platform: nav.platform,
      cores: nav.hardwareConcurrency || 0,
      memory: nav.deviceMemory || 0,
      touch: nav.maxTouchPoints || 0,
      webdriver: nav.webdriver === true,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      tzOffset: new Date().getTimezoneOffset(),
      screen: [screen.width, screen.height, screen.colorDepth, screen.pixelDepth].join("x"),
      dpr: window.devicePixelRatio || 1,
      canvas: await canvasHash(),
      webgl: webglRenderer(),
      plugins: plug.plugins,
      mimeTypes: plug.mimeTypes,
      automation: detectAutomation(), // { score, flags }
      mouse: window.__hv_m || 0,
      scroll: window.__hv_s || 0,
      key: window.__hv_k || 0,
      dwell: Math.round(performance.now()),
    };
    return sig;
  }

  async function canvasHash() {
    try {
      const c = document.createElement("canvas");
      c.width = 240;
      c.height = 60;
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 10, 80, 30);
      ctx.fillStyle = "#069";
      ctx.fillText("human-verify", 12, 14);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("human-verify", 14, 16);
      const data = ctx.getImageData(0, 0, c.width, c.height).data;
      let h = "";
      for (let i = 0; i < data.length; i += 97) h += data[i].toString(16);
      return h || "na";
    } catch {
      return "na";
    }
  }

  function webglRenderer() {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "no-gl";
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "gl";
    } catch {
      return "na";
    }
  }

  async function hashSignals(sig) {
    const enc = (s) => new TextEncoder().encode(s);
    const hex = (buf) =>
      Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return hex(await crypto.subtle.digest("SHA-256", enc(JSON.stringify(sig))));
  }

  function scoreSignals(sig) {
    let s = 0;
    if (!sig.webdriver) s += 30;
    if (sig.cores >= 2) s += 15;
    if (sig.canvas && sig.canvas !== "na") s += 20;
    if (sig.webgl && sig.webgl !== "no-gl" && sig.webgl !== "na") s += 15;
    if (sig.plugins && sig.plugins.length > 0) s += 5; // 有插件更像真实浏览器环境
    if (sig.mouse > 3 || sig.scroll > 0 || sig.key > 0) s += 15;
    if (sig.automation && sig.automation.score >= 40) s -= 40; // 自动化特征强则扣可信度
    return Math.max(0, Math.min(100, s));
  }

  async function verify() {
    const ch = await (await fetch(API_BASE + "/challenge")).json();
    if (!ch.ok) throw new Error(ch.error || "challenge failed");
    const sig = await collectSignals();
    const sh = await hashSignals(sig);
    const score = scoreSignals(sig);
    const automationScore = sig.automation.score;

    const nonce = await new Promise((resolve, reject) => {
      const w = makeWorker();
      w.onmessage = (e) => {
        w.terminate();
        resolve(e.data.nonce);
      };
      w.onerror = (e) => {
        w.terminate();
        reject(e);
      };
      w.postMessage({ challenge: ch.challenge, signalsHash: sh, difficulty: ch.difficulty });
    });
    if (!nonce) throw new Error("pow timeout");

    const v = await (
      await fetch(API_BASE + "/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: ch.token, powNonce: nonce, signalsHash: sh, score, automationScore }),
      })
    ).json();
    if (!v.ok) throw new Error(v.error || "verify failed");
    lastRisk = v.risk || null;
    return v.verification;
  }

  function applyResult(btn, token, opts, risk) {
    if (btn) btn.dataset.token = token;
    const inputSel = btn && btn.dataset.input;
    if (inputSel) {
      const el = document.querySelector(inputSel);
      if (el) el.value = token;
    }
    if (opts && typeof opts.onVerified === "function") opts.onVerified(token, btn, risk);
    else if (btn && btn.dataset.callback && typeof window[btn.dataset.callback] === "function")
      window[btn.dataset.callback](token, btn, risk);
    else if (typeof window.HumanVerify.onVerified === "function")
      window.HumanVerify.onVerified(token, btn, risk);
  }

  function bind(btn, opts) {
    if (btn.__hvBound) return;
    btn.__hvBound = true;
    btn.dataset.label = btn.dataset.label || btn.textContent;
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      if (btn.disabled) return;
      try {
        btn.disabled = true;
        const old = btn.textContent;
        btn.textContent = "验证中…";
        const token = await verify();
        const risk = lastRisk;
        btn.textContent = "✅ 验证成功";
        btn.classList.add("hv-verified");
        applyResult(btn, token, opts, risk);
      } catch (err) {
        btn.textContent = btn.dataset.label || "点击验证";
        btn.disabled = false;
        btn.classList.remove("hv-verified");
        alert("验证失败：" + err.message);
      }
    });
  }

  function autoBind() {
    document
      .querySelectorAll("button[data-human-verify], [data-human-verify]")
      .forEach((btn) => bind(btn));
  }

  window.HumanVerify = {
    verify,
    render(selector, opts) {
      const el = typeof selector === "string" ? document.querySelector(selector) : selector;
      if (el) bind(el, opts || {});
      return el;
    },
    onVerified: null,
    get lastRisk() {
      return lastRisk;
    },
  };

  if (document.readyState !== "loading") autoBind();
  else document.addEventListener("DOMContentLoaded", autoBind);
})();
