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
comes back as `-32029` with a `retry_after_seconds` hint):

- `security-suite.mjs` sleeps 2.2s between cases.
- `contract-frontend-test.mjs` gates `fetch` through a sliding 28-per-minute
  window, because the frontend helpers it calls in Phase C issue several RPCs
  each — per-case sleeping would still overrun.

A full run therefore takes a few minutes. Wait at least a minute between
consecutive runs: the limit is enforced per caller on the server, so a suite
started while the previous run's window is still hot will fail on its first
calls regardless of its own pacing.
