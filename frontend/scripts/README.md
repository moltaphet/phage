# Live contract test scripts

Read-only / dry-run suites that exercise the deployed PhageSentinel contract on
GenLayer Studio-dev through the frontend's own client code. Neither spends funds
or mutates state: `security-suite.mjs` uses `simulateWriteContract`, and
`contract-frontend-test.mjs` uses `readContract` plus dry-run writes.

```bash
cd frontend
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/security-suite.mjs
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/contract-frontend-test.mjs
```

`ts-resolve*.mjs` is a small Node loader hook that lets these `.mjs` scripts
import the frontend's TypeScript modules directly, so the tests exercise the
real `src/lib/genlayer.ts` code rather than a reimplementation of it. It also
needs `--experimental-strip-types`, since those modules are TypeScript.

Both suites stay under the node's limit of **30 requests per minute** (the 31st
comes back as `-32029` with a `retry_after_seconds` hint). Each one gates
`fetch` through the same sliding 28-per-minute window rather than sleeping
between cases, because the frontend helpers `contract-frontend-test.mjs` calls
in Phase C issue several RPCs per call — per-case sleeping would still overrun.

The window is what makes back-to-back runs safe: the counter lives in the
server-side 60s window, not in the script, so a suite started while the previous
run's requests are still inside it simply waits rather than failing. A full run
takes roughly a minute per 28 requests.
