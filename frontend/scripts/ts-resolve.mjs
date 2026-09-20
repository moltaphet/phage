import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('.')) {
    try { return await next(specifier, context); } catch (err) {
      for (const ext of ['.ts', '.tsx', '/index.ts']) {
        const url = new URL(specifier + ext, context.parentURL);
        if (existsSync(fileURLToPath(url))) return next(specifier + ext, context);
      }
      throw err;
    }
  }
  return next(specifier, context);
}
