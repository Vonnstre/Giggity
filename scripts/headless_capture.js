#!/usr/bin/env node
// scripts/headless_capture.js
// Usage: node scripts/headless_capture.js <host> <evidenceDir> <rawDir> "<UA>"
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

(async () => {
  const [,, host, evidenceDir, rawDir, ua] = process.argv;
  if (!host) { console.error("usage: node headless_capture.js <host> <evidenceDir> <rawDir> \"<UA>\");"); process.exit(2); }

  const url = `https://${host}`;
  const harPath = path.join(evidenceDir, "har", `${host}.har`);
  const pngPath = path.join(evidenceDir, "screens", `${host}.png`);
  const sessionsPath = path.join(rawDir, "sessions.jsonl");
  const apisPath = path.join(rawDir, "discovered_apis.jsonl");

  [path.dirname(harPath), path.dirname(pngPath), path.dirname(sessionsPath), path.dirname(apisPath)]
    .forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

  const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox","--disable-setuid-sandbox"] });
  try {
    const page = await browser.newPage();
    await page.setUserAgent(ua || "PassiveEnum/1.0");
    await page.setViewport({ width: 1366, height: 900 });

    const requests = [];
    page.on("requestfinished", async (req) => {
      try {
        const res = await req.response();
        requests.push({ url: req.url(), method: req.method(), status: res ? res.status() : 0, ct: res ? res.headers()["content-type"]||"" : "" });
      } catch {}
    });

    try { await page.goto(url, { waitUntil: "networkidle2", timeout: 30000 }); } catch(e){}
    try { await page.screenshot({ path: pngPath, fullPage: false }); } catch(e){}

    const cookies = await page.cookies();
    const localStorageCapture = await page.evaluate(() => {
      const out = {}; try { for (let i=0;i<localStorage.length;i++){ const k=localStorage.key(i); out[k]=localStorage.getItem(k);} } catch(e){}
      return out;
    });

    fs.writeFileSync(harPath, JSON.stringify({ host, requests, ts: Date.now() }, null, 2));
    fs.appendFileSync(sessionsPath, JSON.stringify({ host, cookies, localStorage: localStorageCapture, ts: Date.now() }) + "\n");

    const apiGuesses = Array.from(new Set(requests.map(r => r.url).filter(u => /\/api\/|\/v\d+\/|graphql|\/admin\/|\/auth\/|openapi|swagger|health|metrics/i.test(u))));
    apiGuesses.forEach(u => fs.appendFileSync(apisPath, JSON.stringify({ host, url: u }) + "\n"));

    console.log(`[headless] ${host} -> ${apiGuesses.length} endpoints`);
    await page.close();
  } catch (e) {
    console.error("[headless] error:", e && e.message ? e.message : e);
  } finally { try { await browser.close(); } catch(e){} }
})();
