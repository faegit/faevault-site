import { withBase } from '../config/site';

export const locales = ['zh-cn', 'en'] as const;
export type Locale = (typeof locales)[number];

export const localeMeta: Record<Locale, { label: string; htmlLang: string }> = {
  'zh-cn': { label: '中文', htmlLang: 'zh-CN' },
  en: { label: 'English', htmlLang: 'en' },
};

export const uiText = {
  'zh-cn': {
    nav: { home: '首页', guides: '使用指南', journey: '开发历程', download: '下载', support: '支持' },
    switchLanguage: 'English',
    skipToContent: '跳到正文',
  },
  en: {
    nav: { home: 'Home', guides: 'Guides', journey: 'Journey', download: 'Download', support: 'Support' },
    switchLanguage: '中文',
    skipToContent: 'Skip to content',
  },
} satisfies Record<Locale, object>;

export function isLocale(value: string): value is Locale {
  return locales.includes(value as Locale);
}

export function otherLocale(locale: Locale): Locale {
  return locale === 'zh-cn' ? 'en' : 'zh-cn';
}

export function localePath(locale: Locale, routePath = '/'): string {
  const normalized = routePath === '/' ? '' : `/${routePath.replace(/^\/+|\/+$/g, '')}`;
  return withBase(`/${locale}${normalized}/`);
}
