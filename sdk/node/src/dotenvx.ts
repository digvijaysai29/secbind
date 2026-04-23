import { loadSecrets, LoaderOptions } from './loader';

export interface ConfigOutput {
  parsed: Record<string, string>;
}

export function config(opts: LoaderOptions = {}): ConfigOutput {
  const parsed = loadSecrets(opts);
  for (const [key, value] of Object.entries(parsed)) {
    if (opts.override || process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return { parsed };
}
