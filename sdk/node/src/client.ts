export function parseKeyValue(output: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf('=');
    if (idx > 0) {
      result[trimmed.slice(0, idx)] = trimmed.slice(idx + 1);
    }
  }
  return result;
}
