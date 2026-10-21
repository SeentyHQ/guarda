export function redact(value: string): string {
  if (value.length >= 10) return `${value.slice(0, 4)}…(${value.length} chars)…${value.slice(-2)}`;
  return `${value.slice(0, 2)}…(${value.length} chars)`;
}
