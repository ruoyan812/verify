/**
 * 自研点击式人机验证 Worker（不依赖 Turnstile）
 *
 * 安全模型：
 *   1) 前端点击按钮 → GET /challenge 获取【服务端 HMAC 签名 + 过期】的挑战令牌。
 *   2) 前端静默采集环境指纹（含自动化工具特征、插件）并求解 PoW（算力证明）。
 *   3) POST /verify：服务端校验 ①挑战签名/过期 ②（KV）防重放 ③PoW 难度，
 *      通过则签发 verification token。
 *   4) 服务端【可信】IP 信誉（Cloudflare request.cf：ASN/国家/TLS）+ KV 黑名单硬拒，
 *      并按风险自适应提高 PoW 难度。
 *
 * 说明：前端插件/自动化特征是【客户端信号】，可被高级机器人伪造，仅作参考评分与
 *      PoW 输入，不作为放行依据。真正的成本与可信判定来自「签名挑战 + PoW 算力 +
 *      服务端 IP 信誉」。生产建议叠加 Cloudflare Bot Management。
 */

const CHALLENGE_TTL = 120; // 挑战令牌有效期（秒）
const VERIFY_TTL = 300; // 验证令牌有效期（秒）
const DEFAULT_DIFFICULTY = 16; // PoW 前导 0 比特数（16 ≈ 6.5 万次哈希，浏览器亚百毫秒）

// 常见云厂商 / 数据中心 ASN（命中则更可能是爬虫 / 自动化服务器）
const DATACENTER_ASNS = new Set([
  16509, 14618, 15169, 8075, 53831, 210644, // AWS, Azure
  14061, 63949, 20473, 31898, 24940, 9009, // DO, Linode, Vultr, Oracle, Hetzner, M247
  45102, 37963, 4837, 4134, // 阿里云, 腾讯云, 联通, 电信
]);

// ---------- Web Crypto 工具 ----------

function enc(str) {
  return new TextEncoder().encode(str);
}
function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function toB64url(bytes) {
  let s = "";
  new Uint8Array(bytes).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function randomHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return bufToHex(a);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// HMAC 密钥按需导入并缓存在 module 作用域（同 isolate 生命周期内复用）
let _hmacKeyPromise = null;
function hmacKey(secret) {
  if (!_hmacKeyPromise) {
    _hmacKeyPromise = crypto.subtle.importKey(
      "raw",
      enc(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  }
  return _hmacKeyPromise;
}

async function hmacHex(dataStr, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc(dataStr));
  return bufToHex(sig);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", enc(str));
  return bufToHex(buf);
}

async function sign(obj, secret) {
  const payload = toB64url(enc(JSON.stringify(obj)));
  const sig = await hmacHex(payload, secret);
  return `${payload}.${sig}`;
}

async function verifyToken(tokenStr, secret) {
  if (typeof tokenStr !== "string" || !tokenStr.includes(".")) return null;
  const [payload, sig] = tokenStr.split(".");
  const expect = await hmacHex(payload, secret);
  if (!timingSafeEqual(expect, sig)) return null;
  let obj;
  try {
    obj = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
  } catch {
    return null;
  }
  if (!obj.exp || obj.exp < Math.floor(Date.now() / 1000)) return null;
  return obj;
}

// PoW 难度判定：统计十六进制哈希字符串的前导 0 比特数
function leadingZeroBits(hex) {
  let bits = 0;
  for (const ch of hex) {
    const v = parseInt(ch, 16);
    if (v === 0) {
      bits += 4;
    } else {
      bits += Math.clz32(v) - 28; // 4 位中前导 0 个数
      break;
    }
  }
  return bits;
}

// ---------- IP 信誉（服务端可信，基于 Cloudflare 边缘信号）----------

function assessIpRisk(request) {
  const cf = request.cf || {};
  const rawIp = request.headers.get("CF-Connecting-IP") || cf.ip || null;
  let risk = 0;
  const reasons = [];
  const asn = cf.asn || 0;
  if (DATACENTER_ASNS.has(asn)) {
    risk += 50;
    reasons.push("datacenter-asn");
  }
  const tls = cf.tlsVersion || "";
  if (tls === "none") {
    risk += 15;
    reasons.push("no-tls");
  }
  // 扩展点：可在此接入 AbuseIPDB / IPQualityScore 等第三方 IP 信誉 API
  // （需 env 配置 key，并对 rawIp 发起查询）。默认仅用 Cloudflare 边缘信号。
  return {
    rawIp,
    ip: rawIp ? rawIp.replace(/\.\d+$/, ".x") : null, // 脱敏，仅留网段用于日志
    asn,
    country: cf.country || null,
    tls: tls || null,
    risk: Math.min(100, risk),
    reasons,
  };
}

// ---------- 响应工具 ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      // 允许跨站嵌入该验证脚本（验证仍依赖签名挑战，跨域无法伪造）
      "access-control-allow-origin": "*",
    },
  });
}

// ---------- 路由处理 ----------

async function handleChallenge(request, env) {
  const secret = env.HUMAN_SECRET;
  if (!secret) return json({ ok: false, error: "server misconfigured" }, 500);

  // IP 信誉评估（基于 Cloudflare 边缘信号，客户端无法篡改）
  const ip = assessIpRisk(request);

  // KV 黑名单硬拒（命中直接 403，省去算力）
  if (env.VERIFY_KV && ip.rawIp) {
    const banned = await env.VERIFY_KV.get(`ban:${ip.rawIp}`);
    if (banned) return json({ ok: false, error: "blocked" }, 403);
  }

  // 自适应 PoW 难度：IP 风险越高，要求算力越大
  const base = Number(env.DIFFICULTY) || DEFAULT_DIFFICULTY;
  const difficulty = ip.risk >= 50 ? base + 8 : ip.risk >= 20 ? base + 4 : base;

  const now = Math.floor(Date.now() / 1000);
  const obj = {
    jti: randomHex(16),
    challenge: randomHex(24),
    difficulty,
    ipRisk: ip.risk,
    asn: ip.asn,
    country: ip.country,
    exp: now + CHALLENGE_TTL,
  };
  const token = await sign(obj, secret);
  // challenge 是公开随机数（nonce），可随响应直接下发给前端用于计算 PoW
  return json({ ok: true, token, challenge: obj.challenge, difficulty, ttl: CHALLENGE_TTL });
}

async function handleVerify(request, env) {
  const secret = env.HUMAN_SECRET;
  if (!secret) return json({ ok: false, error: "server misconfigured" }, 500);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "bad request" }, 400);
  }

  const { token, powNonce, signalsHash, automationScore } = body;
  if (typeof token !== "string" || typeof powNonce !== "string" || typeof signalsHash !== "string") {
    return json({ ok: false, error: "missing fields" }, 400);
  }
  if (powNonce.length > 64 || signalsHash.length > 128) {
    return json({ ok: false, error: "field too long" }, 400);
  }

  // 1) 校验挑战令牌签名 + 过期
  const claims = await verifyToken(token, secret);
  if (!claims) return json({ ok: false, error: "invalid or expired challenge" }, 403);

  // 2) 可选：KV 防重放（标记 jti 已使用）
  if (env.VERIFY_KV) {
    const used = await env.VERIFY_KV.get(`used:${claims.jti}`);
    if (used) return json({ ok: false, error: "replay detected" }, 403);
  }

  // 3) 校验 PoW：sha256(challenge | signalsHash | powNonce) 前导 0 比特数 >= 难度
  const digest = await sha256Hex(`${claims.challenge}|${signalsHash}|${powNonce}`);
  if (leadingZeroBits(digest) < claims.difficulty) {
    return json({ ok: false, error: "proof of work failed" }, 403);
  }

  // 4) 通过：消费 jti + 签发 verification token（附带风险画像供业务后端参考）
  if (env.VERIFY_KV) {
    await env.VERIFY_KV.put(`used:${claims.jti}`, "1", { expirationTtl: CHALLENGE_TTL });
  }
  const now = Math.floor(Date.now() / 1000);
  const autoScore = typeof automationScore === "number" ? automationScore : null;
  const verification = await sign(
    {
      jti: randomHex(16),
      action: "human-verified",
      score: typeof body.score === "number" ? body.score : null, // 前端真人可信度，仅记录
      automationScore: autoScore, // 前端自动化特征分，仅记录（客户端信号不可信）
      ipRisk: claims.ipRisk ?? null, // 服务端 IP 信誉（可信）
      asn: claims.asn ?? null,
      country: claims.country ?? null,
      exp: now + VERIFY_TTL,
    },
    secret,
  );
  return json({
    ok: true,
    verification,
    ttl: VERIFY_TTL,
    risk: {
      ipRisk: claims.ipRisk ?? null,
      automationScore: autoScore,
      asn: claims.asn ?? null,
      country: claims.country ?? null,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/challenge") {
      return handleChallenge(request, env);
    }
    if (request.method === "POST" && url.pathname === "/verify") {
      return handleVerify(request, env);
    }

    // 其余请求：从静态资源目录提供前端页面
    return env.ASSETS.fetch(request);
  },
};
