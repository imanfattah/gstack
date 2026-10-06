import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

const root = path.resolve(import.meta.dir, "..");
const rendererRequire = createRequire(path.join(root, "lib/diagram-render/package.json"));

test("OSV fixes resolve every affected root package to its security pin", async () => {
  const lock = await Bun.file(path.join(root, "bun.lock")).text();
  for (const [name, version] of Object.entries({
    "adm-zip": "0.6.1", "fast-uri": "3.1.8", hono: "4.13.7",
    "ip-address": "10.7.1", sharp: "0.35.4",
    roarr: "3.3.0", "proxy-addr": "2.0.8",
  })) {
    const resolutions = [...lock.matchAll(new RegExp(`"${name}@([^"\\s]+)"`, "g"))];
    expect(resolutions.length).toBeGreaterThan(0);
    for (const resolution of resolutions) expect(resolution[1]).toBe(version);
  }
});

test("renderer removes vulnerable braces chain and pins patched DOMPurify", async () => {
  const lock = await Bun.file(path.join(root, "lib/diagram-render/bun.lock")).text();
  expect(lock).not.toMatch(/"braces@/);
  expect(lock).toContain('"dompurify@3.4.16"');
  expect(lock).toContain('"sass@1.93.3"');
  expect(lock).toContain('"katex@0.18.2"');
  expect(lock).toContain('"source-map-js@1.2.2"');
});

test("sprintf-js is absent and the installer proxy API remains available with logging", async () => {
  const lock = await Bun.file(path.join(root, "bun.lock")).text();
  expect(lock).not.toMatch(/"sprintf-js@/);
  // Preserve the diagnostics dependency rather than choosing the newer no-op logger.
  expect(lock).toContain('"roarr@');
  const proxy = await import("global-agent");
  expect(typeof proxy.bootstrap).toBe("function");
  expect(typeof proxy.createGlobalProxyAgent).toBe("function");
});

test("replacement formatter explicitly rejects excessive precision without aborting logging", async () => {
  const { printf, createPrintf } = await import("fast-printf");
  for (const format of [printf, createPrintf()]) {
    for (const subject of ["%.101f", "%1$.999f", `%.${"9".repeat(400)}f`]) {
      expect(format(subject, 1)).toContain("[invalid numeric precision]");
    }
    expect(format("%.0f", 1.5)).toBe("2");
    expect(format("%.2f", 1.25)).toBe("1.25");
    expect(format("%.100f", 1)).toHaveLength(102);
    expect(format("proxy %s, status %d", "local", 200)).toBe("proxy local, status 200");
    expect(format("constructor")).toBe("constructor");
    expect(format("__proto__")).toBe("__proto__");
    expect(format("%.2g", 1.25)).toBe("1.3");
    expect(format("%.101g", 1)).toContain("[invalid numeric precision]");
    expect(format("%999999999999999999999999999999999999999.2f", 1)).toContain("[invalid numeric width]");
    expect(format("%8.2f", 1.25)).toBe("    1.25");
  }
});

test("installer proxy routes requests, honors NO_PROXY and emits diagnostics", async () => {
  let proxiedRequests = 0;
  const proxy = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch() {
    proxiedRequests++;
    return new Response("proxied");
  } });
  const target = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch() {
    return new Response("direct");
  } });
  try {
    // Isolate bootstrap's global HTTP mutations from this test process.
    const script = `
      const http = require("node:http");
      require("global-agent").bootstrap();
      const get = url => new Promise((resolve, reject) => {
        http.get(url, response => {
          let body = "";
          response.on("data", chunk => body += chunk);
          response.on("end", () => resolve(body));
        }).on("error", reject);
      });
      (async () => {
        const proxied = await get("http://example.invalid/security-control");
        global.GLOBAL_AGENT.NO_PROXY = "127.0.0.1";
        const direct = await get("http://127.0.0.1:${target.port}/control");
        console.log(JSON.stringify({ proxied, direct }));
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `;
    // ONNX's installer runs under Node, not Bun's HTTP compatibility layer.
    const node = Bun.which("node");
    if (!node) throw new Error("Node.js is required for the ONNX installer proxy regression");
    const child = Bun.spawn([node, "-e", script], {
      cwd: root,
      env: { ...process.env, ROARR_LOG: "true",
        GLOBAL_AGENT_HTTP_PROXY: `http://127.0.0.1:${proxy.port}`,
        GLOBAL_AGENT_HTTPS_PROXY: "", GLOBAL_AGENT_NO_PROXY: "",
        GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE: "GLOBAL_AGENT_",
        GLOBAL_AGENT_FORCE_GLOBAL_AGENT: "true", GLOBAL_AGENT_SOCKET_CONNECTION_TIMEOUT: "2000",
      },
      stdout: "pipe", stderr: "pipe",
    });
    const [stdout, stderr, exit] = await Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    if (exit !== 0) throw new Error(`proxy child exited ${exit}: ${stderr}`);
    expect(stderr).not.toContain("Error:");
    expect(stdout).toContain('"proxied":"proxied","direct":"direct"');
    expect(stdout).toContain('"package":"global-agent"');
    expect(proxiedRequests).toBe(1);
  } finally {
    proxy.stop(true); target.stop(true);
  }
}, 10000);

test("proxy trust rejects short IPv4-mapped subnet prefixes and preserves valid IPv4 blocks", async () => {
  const proxyAddr = (await import("proxy-addr")).default;
  for (const range of ["::ffff:10.0.0.0/8", "::/1"]) {
    expect(proxyAddr.compile(range)("203.0.113.1", 0)).toBe(false);
  }
  const ordinary = proxyAddr.compile("10.0.0.0/8");
  expect(ordinary("10.20.30.40", 0)).toBe(true);
  expect(ordinary("203.0.113.1", 0)).toBe(false);
  const mapped = proxyAddr.compile("::ffff:10.0.0.0/104");
  expect(mapped("10.20.30.40", 0)).toBe(true);
  expect(mapped("203.0.113.1", 0)).toBe(false);
});

test("indexed source maps reject extreme or invalid offsets while decoding ordinary sections", () => {
  const { SourceMapConsumer } = rendererRequire("source-map-js");
  const sourceMap = (line: number) => ({
    version: 3, sections: [{ offset: { line, column: 0 }, map: {
      version: 3, sources: ["input.js"], names: [], mappings: "AAAA",
    } }],
  });
  for (const offset of [Number.MAX_SAFE_INTEGER, Infinity, -1, 1.5]) {
    expect(() => new SourceMapConsumer(sourceMap(offset))).toThrow();
  }
  const ordinary = new SourceMapConsumer(sourceMap(0));
  expect(ordinary.originalPositionFor({ line: 1, column: 1 }).source).toBe("input.js");
});

test("KaTeX ignores inherited trust and still renders ordinary math", () => {
  const katex = rendererRequire("katex");
  const expression = String.raw`\href{javascript:alert(1)}{click}`;
  const inheritedOptions = Object.create({ trust: true });
  const output = katex.renderToString(expression, inheritedOptions);
  expect(output).not.toContain('href="javascript:');
  expect(katex.renderToString("x^2 + y^2")).toContain("katex");
});

test("ZIP extraction cannot overwrite through a destination symlink; ordinary extraction works", async () => {
  const AdmZip = (await import("adm-zip")).default;
  const base = mkdtempSync(path.join(tmpdir(), "gstack-zip-regression-"));
  try {
    const outside = path.join(base, "outside");
    const destination = path.join(base, "destination");
    mkdirSync(outside); mkdirSync(destination);
    writeFileSync(path.join(outside, "target.txt"), "original");
    symlinkSync(outside, path.join(destination, "linked"), "junction");
    const malicious = new AdmZip();
    malicious.addFile("linked/target.txt", Buffer.from("overwritten"));
    try { malicious.extractAllTo(destination, true); } catch {}
    expect(readFileSync(path.join(outside, "target.txt"), "utf8")).toBe("original");
    // Equivalent single-entry extraction must not bypass the same boundary.
    try { malicious.extractEntryTo("linked/target.txt", destination, true, true); } catch {}
    expect(readFileSync(path.join(outside, "target.txt"), "utf8")).toBe("original");
    const ordinary = new AdmZip();
    ordinary.addFile("safe/file.txt", Buffer.from("expected"));
    ordinary.extractAllTo(destination, true);
    expect(readFileSync(path.join(destination, "safe/file.txt"), "utf8")).toBe("expected");
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("ip-address recognizes the full link-local range without rejecting ordinary global addresses", async () => {
  const { Address6 } = await import("ip-address");
  expect(new Address6("febf::1").isLinkLocal()).toBe(true);
  expect(new Address6("fe80::1").isLinkLocal()).toBe(true);
  expect(new Address6("2001:4860:4860::8888").isLinkLocal()).toBe(false);
});
