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
