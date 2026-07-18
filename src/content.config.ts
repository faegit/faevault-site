import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const localizedBase = z.object({
  title: z.string().min(1),
  description: z.string().min(1),
  locale: z.enum(['zh-cn', 'en']),
  translationKey: z.string().min(1),
  order: z.number().int().nonnegative().default(0),
  draft: z.boolean().default(false),
});

const guides = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/guides' }),
  schema: localizedBase.extend({
    section: z.enum(['start', 'vault', 'autofill', 'passkeys', 'sync', 'security']),
    platforms: z.array(z.enum(['android', 'windows'])).min(1),
  }),
});

const stories = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/stories' }),
  schema: localizedBase.extend({
    publishedAt: z.coerce.date(),
    coverImage: z.string().optional(),
  }),
});

const releases = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/releases' }),
  schema: localizedBase.extend({
    version: z.string().min(1),
    publishedAt: z.coerce.date(),
    githubReleaseUrl: z.url(),
  }),
});

const legal = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/legal' }),
  schema: localizedBase,
});

export const collections = { guides, stories, releases, legal };
