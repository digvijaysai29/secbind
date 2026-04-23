import { execFileSync } from 'child_process';
import { parseKeyValue } from './client';

export interface LoaderOptions {
  env?: string;
  file?: string;
  secbindBin?: string;
  override?: boolean;
}

export function loadSecrets(opts: LoaderOptions = {}): Record<string, string> {
  const bin = opts.secbindBin ?? 'secbind';
  const args = ['export', '--env', opts.env ?? 'default'];
  if (opts.file) {
    args.push('--file', opts.file);
  }
  const output = execFileSync(bin, args, { encoding: 'utf8' });
  return parseKeyValue(output);
}
