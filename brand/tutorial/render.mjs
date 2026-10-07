// Render a tutorial chapter with headless Chrome, frame by frame.
//
//   node render.mjs stills CH 1.5,9,15        PNG stills -> out/stills/CH/
//   node render.mjs video CH [fps] [blur]     out/video/CH.mp4 (no audio), cues -> out/cues/CH.json
//
// Needs the repo served at http://127.0.0.1:8803 (build.sh starts it).
// blur = sub-frames per output frame (2 = motion blur by blending two
// samples per frame, like a 180-degree shutter).
import fs from "node:fs";
import { spawn } from "node:child_process";
import puppeteer from "puppeteer-core";

const [mode = "stills", ch = "3-send", arg = "", blurArg = ""] = process.argv.slice(2);
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const browser = await puppeteer.launch({
  executablePath: CHROME, headless: true,
  args: ["--no-sandbox", "--use-angle=metal", "--ignore-gpu-blocklist", "--hide-scrollbars", "--force-color-profile=srgb", "--font-render-hinting=none"],
  defaultViewport: { width: 1920, height: 1080, deviceScaleFactor: 1 },
});
const page = await browser.newPage();
await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "dark" }]);
await page.setUserAgent((await browser.userAgent()).replace("Headless", "") + " Macintosh");
page.on("pageerror", (e) => console.log("PAGE ERROR", e.message));
page.on("console", (m) => { if (/unmocked|not found|error/i.test(m.text())) console.log("PAGE:", m.text()); });
await page.goto(`http://127.0.0.1:8803/brand/tutorial/stage.html?ch=${ch}`);
await page.waitForFunction("window.ready === true", { timeout: 60000 });
const duration = await page.evaluate(() => window.DURATION);
fs.mkdirSync("out/cues", { recursive: true });
fs.writeFileSync(`out/cues/${ch}.json`, JSON.stringify(await page.evaluate(() => window.CUES)));

if (mode === "cam") {
  // Debug: where the camera is at the given times.
  for (const t of arg.split(",").map(Number)) {
    console.log(t, JSON.stringify(await page.evaluate(async (t) => { await window.renderAt(t); return window.E.cameraAt(t); }, t)));
  }
} else if (mode === "stills") {
  const dir = `out/stills/${ch}`;
  fs.mkdirSync(dir, { recursive: true });
  const times = arg ? arg.split(",").map(Number) : Array.from({ length: 12 }, (_, i) => +(duration * (i + 0.5) / 12).toFixed(2));
  for (const t of times.sort((a, b) => a - b)) {
    await page.evaluate((t) => window.renderAt(t), t);
    await page.screenshot({ path: `${dir}/t${t.toFixed(2).padStart(6, "0")}.png` });
  }
  console.log(`${times.length} stills in ${dir}`);
} else {
  const fps = Number(arg || 60), blur = Number(blurArg || 2);
  const N = Math.ceil(duration * fps);
  fs.mkdirSync("out/video", { recursive: true });
  const out = `out/video/${ch}.mp4`;
  const vf = blur > 1 ? ["-vf", `tmix=frames=${blur}:weights='${Array(blur).fill(1).join(" ")}',framestep=${blur}`] : [];
  const ff = spawn("ffmpeg", ["-loglevel", "error", "-y", "-f", "image2pipe", "-framerate", String(fps * blur), "-i", "-",
    ...vf, "-r", String(fps), "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-pix_fmt", "yuv420p", "-profile:v", "high", out],
  { stdio: ["pipe", "inherit", "inherit"] });
  const t0 = Date.now();
  for (let i = 0; i < N * blur; i++) {
    const t = i / (fps * blur);
    await page.evaluate((t) => window.renderAt(t), t);
    const buf = await page.screenshot({ type: "png", optimizeForSpeed: true });
    if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once("drain", r));
    if (i % (fps * blur * 5) === 0) console.log(`${ch}: ${(t).toFixed(1)}/${duration.toFixed(1)} s  (${((Date.now() - t0) / 1000).toFixed(0)} s)`);
  }
  ff.stdin.end();
  await new Promise((r) => ff.on("close", r));
  console.log(`${out}  ${N} frames in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
}
await browser.close();
