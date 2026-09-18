export function shortHex(value: string, head = 8, tail = 6): string {
  if (!value) return '';
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function formatIso(iso: string): string {
  if (!iso || iso === 'N/A') return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso.replace('T', ' ').slice(0, 16);
  return date.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

export function tierLabel(tier: string): string {
  return tier.replace(/^TIER_/, '').replaceAll('_', ' ');
}

const ATTO = 10n ** 18n;

// Convert an on-chain atto value (wei-equivalent, 1e18) into a human GEN string.
// Accepts the string returned by the contract's u256 views or a bigint.
export function attoToGen(atto: string | bigint | number, decimals = 4): string {
  let value: bigint;
  try {
    value = typeof atto === 'bigint' ? atto : BigInt(String(atto).trim() || '0');
  } catch {
    return '0.0000';
  }
  const whole = value / ATTO;
  const scale = 10n ** BigInt(decimals);
  const frac = ((value % ATTO) * scale) / ATTO;
  return `${whole.toString()}.${frac.toString().padStart(decimals, '0')}`;
}

// Parse a decimal GEN string (e.g. "0.10") into an atto bigint for tx `value`.
export function genToAtto(gen: string | number): bigint {
  const raw = String(gen).trim();
  if (!raw || Number.isNaN(Number(raw))) return 0n;
  const negative = raw.startsWith('-');
  const [wholePart, fracPartRaw = ''] = raw.replace('-', '').split('.');
  const fracPart = (fracPartRaw + '0'.repeat(18)).slice(0, 18);
  const whole = BigInt(wholePart || '0');
  const frac = BigInt(fracPart || '0');
  const total = whole * ATTO + frac;
  return negative ? -total : total;
}
