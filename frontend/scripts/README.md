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
real `src/lib/genlayer.ts` code rather than a reimplementation of it.

Both suites pace themselves to stay under the node's rate limit (30 requests
per minute); a full run takes a few minutes.
