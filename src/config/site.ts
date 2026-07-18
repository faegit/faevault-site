export const SITE_NAME = 'FAEVault';
export const SITE_ORIGIN = 'https://faegit.github.io';
export const SITE_BASE_PATH = '/faevault-site';
export const DEFAULT_LOCALE = 'zh-cn' as const;

function normalizePath(path: string): string {
  const value = path.startsWith('/') ? path : `/${path}`;
  return value === '/' ? '/' : `${value.replace(/\/+$/, '')}/`;
}

export function withBase(path = '/'): string {
  return `${SITE_BASE_PATH}${normalizePath(path)}`;
}

export function absoluteUrl(path = '/'): string {
  return new URL(withBase(path), SITE_ORIGIN).toString();
}

export function withBaseAsset(path: string): string {
  return `${SITE_BASE_PATH}/${path.replace(/^\/+/, '')}`;
}
