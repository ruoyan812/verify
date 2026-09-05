# 点击式人机验证 Worker（自研，不依赖 Turnstile）

一个完全自托管的 Cloudflare Worker 人机验证方案。通过 `<script src="...">` 引入一个脚本，
页面上放一个按钮，**点击后**才开始验证，验证通过后回调返回 token（类似 Turnstile 的点击式
widget，但完全自己实现，不依赖任何外部验证码服务）。

## 工作原理

```
页面：<script src=".../human-verify.js"> + <button data-human-verify>

用户点击按钮
  │
  ├─ GET /challenge ──────────────►  Worker 签发 HMAC 签名 + 过期时间的挑战令牌
  │     ◄──────────────────────────  { token, challenge, difficulty }
  ├─ 采集环境/行为信号 → SHA-256 摘要
  ├─ 隐藏 Web Worker 求解 PoW（不阻塞 UI）
  │     sha256(challenge|signalsHash|nonce) 前导 0 ≥ difficulty
  └─ POST /verify ────────────────►  Worker 校验：签名/exp + PoW 难度 + (KV 防重放)
        ◄──────────────────────────  { verification: 签名令牌 }
  └─ 回调返回 token（写入 data-input 隐藏域 / btn.dataset.token）
```

**为什么能挡机器人**：纯前端信号可被伪造，但本方案的真实成本来自「服务端签名的挑战」+
「浏览器必须付出算力求解 PoW」。没有合法 `token` 就无法构造有效证明，脚本批量刷接口的
成本被显著抬高。

## 文件结构

```
src/worker.js             Worker 入口：/challenge、/verify、静态资源托管
public/human-verify.js     可嵌入验证脚本（自包含 PoW Worker + 点击触发 + 回调）
public/index.html          演示页（点击按钮验证）
wrangler.toml              部署配置（含可选 KV 防重放）
```

## 在你的页面中嵌入（两步）

1. 引入脚本（脚本由你的 Worker 提供，同源或跨站均可）：

   ```html
   <script src="https://你的worker.example.workers.dev/human-verify.js" async></script>
   ```

2. 放一个按钮，并声明回调 / 目标隐藏域：

   ```html
   <button data-human-verify data-callback="onVerified" data-input="#token">
     点击进行人机验证
   </button>
   <input type="hidden" id="token" />

   <script>
     function onVerified(token, btn) {
       // token 即验证通过的凭据，随业务请求带回后端校验
       console.log(token);
     }
   </script>
   ```

也可以编程式调用：

```js
// 绑定到指定按钮
HumanVerify.render("#myBtn", { onVerified: (token) => { /* ... */ } });
// 或直接触发一次验证
const token = await HumanVerify.verify();
```

验证通过后会：写入 `btn.dataset.token`、把 token 填入 `data-input` 指定的隐藏域、调用
`data-callback` 全局函数或 `onVerified` 回调。`token` 单次有效，失败可重试。

## 本地运行

```bash
npm install
# 生成签名密钥并写入本地 .dev.vars（切勿提交）
wrangler secret put HUMAN_SECRET      # 提示输入时粘贴：openssl rand -hex 32 的输出
npm run dev                          # 打开 http://localhost:8787
```

点击页面按钮即可看到验证流程与返回的 token。

## 部署

```bash
wrangler secret put HUMAN_SECRET      # 线上环境的密钥（与本地可不同）
wrangler deploy
```

部署后把脚本 `src` 改成 `https://<your-worker>.<subdomain>.workers.dev/human-verify.js`。

## 防重放（已默认开启 KV）

`wrangler.toml` 已绑定 `VERIFY_KV`。首次部署前创建命名空间，并把返回的 `id` 填入
`wrangler.toml` 的 `id` 字段：

```bash
wrangler kv namespace create VERIFY_KV
# 输出示例： { "id": "abcd1234ef...", "title": "human-verify-worker-VERIFY_KV" }
wrangler deploy
```

Worker 会用 `VERIFY_KV` 记录已消耗的 `jti`（TTL = 挑战有效期），同一挑战被重复使用直接 403。

## 环境指纹与 IP 信誉检测

验证分「前端参考信号」与「服务端可信信号」两层：

- **前端采集（仅供参考，可被高级机器人伪造，仅作评分 + 计入 PoW 输入）**
  - 浏览器插件 / MIME 类型枚举
  - 自动化工具特征：`navigator.webdriver`、ChromeDriver 的 `cdc_` 注入变量、
    UA 关键字（headless/selenium/playwright…）、旧版 headless 缺 `window.chrome`、
    PhantomJS/Nightmare 痕迹、0 尺寸视窗、平台与 UA 不一致等
- **服务端（可信，来自 Cloudflare 边缘，客户端无法篡改）**
  - IP 信誉：基于 `request.cf` 的 ASN / 国家 / TLS 版本，命中云厂商/数据中心 ASN 即加风险
  - KV 黑名单：命中 `ban:<ip>` 直接 403（用 `wrangler kv key put` 维护）

**自适应难度**：IP 风险越高，服务端签发的 PoW 难度越大（风险 ≥20 加 4 比特、≥50 加 8 比特），
真正抬高可疑流量的算力成本。`/verify` 响应与 verification token 的 claims 都附带
`risk`（ipRisk / automationScore / asn / country），供业务后端参考。

> 注意：前端信号不可信，本方案不据此单独拒绝；真正的硬门槛是「签名挑战 + PoW 算力 +
> 服务端 IP 信誉」。要精准识别高级机器人，建议叠加 Cloudflare Bot Management。

### 维护 IP 黑名单

```bash
wrangler kv key put --binding VERIFY_KV "ban:1.2.3.4" "1"
wrangler kv key delete --binding VERIFY_KV "ban:1.2.3.4"
```

## 业务后端校验

前端拿到 token 后随业务请求（登录/注册/评论等）一起发给你的后端；后端用同一个
`HUMAN_SECRET` 验签并检查 `exp` 即可放行：

```js
// 后端示例（Node / Cloudflare Worker 均可，复用相同 HMAC 逻辑）
const ok = await verifyToken(verification, HUMAN_SECRET); // 返回 claims 或 null
if (!ok) return res.status(403).end("forbidden");
// 继续业务处理
```

> 说明：这是教学/自托管级实现，用于轻量防刷与点击式无感体验。若需对抗专业机器人，
> 建议叠加 Cloudflare Bot Management 或官方 Turnstile。
