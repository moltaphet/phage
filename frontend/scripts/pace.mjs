// Cross-process pacing for the studio-dev RPC.
//
// The node caps callers at 30 requests/minute and answers the 31st with -32029. A
// sliding window held in process memory only paces one script: run one suite and then
// another, and the second starts with a fresh empty window while the *server's* 60s
// window still holds the first run's requests — so its opening calls come back -32029
// and get misreported as test failures (the guards that expect a contract [EXPECTED]
// message do not match "rate limit exceeded").
//
// The window therefore lives in a file every script shares, so the counter reflects the
// one the server is actually enforcing. Appends are O_APPEND and therefore atomic, which
// keeps two concurrent processes from losing each other's entries; the cap sits below
// the server's limit so the small read-then-append race cannot overshoot it.
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const WINDOW_MS = 60_000;
const MAX_REQUESTS = 26; // server allows 30; the gap absorbs the cross-process race
const COMPACT_ABOVE = 200; // lines, before the ledger is rewritten with only live stamps
const LEDGER = join(tmpdir(), 'phage-studio-dev-rpc-window');

function liveStamps(now) {
  try {
    return readFileSync(LEDGER, 'utf8')
      .split('\n')
      .map(Number)
      .filter((t) => Number.isFinite(t) && now - t <= WINDOW_MS);
  } catch {
    return []; // no ledger yet, or it was removed between runs
  }
}

export function installRateLimit() {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    for (;;) {
      const now = Date.now();
      const stamps = liveStamps(now).sort((a, b) => a - b);
      if (stamps.length < MAX_REQUESTS) {
        try {
          appendFileSync(LEDGER, `${now}\n`);
          if (stamps.length > COMPACT_ABOVE) writeFileSync(LEDGER, stamps.concat(now).join('\n') + '\n');
        } catch {
          // An unwritable tmpdir should not break the suite; fall through unpaced.
        }
        break;
      }
      await new Promise((r) => setTimeout(r, Math.max(stamps[0] + WINDOW_MS - now + 50, 50)));
    }
    return realFetch(...args);
  };
}
