# OSV dependency maintenance — 6 October 2026

This bounded maintenance change addresses the dependency findings from OSV run
37338784764 and the four additional advisories confirmed by a fresh scan of
the same base revision. It does not change scanner configuration, suppressions,
the public ALUN site, or deployment.

Root security overrides pin adm-zip 0.6.1, fast-uri 3.1.8, Hono 4.13.7,
ip-address 10.7.1, and proxy-addr 2.0.8. Sharp 0.35.4 updates its matching
platform binaries and libvips packages. The renderer pins DOMPurify 3.4.16,
KaTeX 0.18.2, and source-map-js 1.2.2. Sass 1.93.3 removes the old
Chokidar/braces dependency chain. Rebuild the committed renderer and its
BUILD_INFO together whenever those overrides change.

Roarr 3.3.0 removes the unpatched sprintf-js dependency while preserving the
global-agent 3 installer API and structured diagnostics. Its replacement
fast-printf formatter otherwise has an equivalent excessive-precision crash.
The existing Bun patchedDependencies mechanism therefore applies
patches/fast-printf@1.6.10.patch to the exact pinned formatter version.
The shared printf/createPrintf implementation emits an explicit
[invalid numeric precision] diagnostic for out-of-range precision, rather
than aborting a logging operation or silently clamping the requested precision.
Valid fixed precision from 0 through 100 and significant precision from 1
through 100 are preserved. The patch also preserves prototype-named messages
using a null-prototype cache, restores significant-digit formatting, and rejects
numeric widths above 10,000 with an explicit diagnostic instead of allocating
an unbounded padded string.
Do not remove that patch based solely on a clean package-version scan.

The regression tests cover resolution of the security pins, dependency
removal, formatter behavior, installer proxy requests and NO_PROXY, retained
structured logs, trust-subnet handling, source-map offsets, inherited KaTeX
trust, ZIP destination symlinks, ordinary extraction, and IPv6 controls.
Node.js must be on PATH for the installer regression because the real ONNX
installer runs under Node, not Bun's HTTP compatibility layer.

Verification commands:

```sh
bun install --frozen-lockfile --ignore-scripts
bun run build:gates
bun test test/osv-dependency-regression.test.ts test/deps-smoke.test.ts \
  test/osv-config-wiring.test.ts test/diagram-render-drift.test.ts \
  test/agent-sdk-runner.test.ts browse/test/socks-bridge.test.ts \
  browse/test/screenshot-size-guard.test.ts make-pdf/test/diagram-prepass.test.ts
osv-scanner scan source --config=.osv-scanner.toml --include-git-root --recursive ./
```

A clean configured scan is not a claim of zero security risk: existing,
time-limited exceptions remain unchanged. ONNX installation on all platforms,
hostile temporary-directory races, and a full live SDK evaluation are outside
this dependency correction. No ALUN production compromise was established.
