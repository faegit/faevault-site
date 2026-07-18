import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REQUIRED_LOCALES = ['zh-cn', 'en'];
export const COLLECTIONS = ['guides', 'stories', 'releases', 'legal'];

function parseFrontmatter(source, filename) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) throw new Error(`${filename}: missing frontmatter`);

  const values = {};
  for (const line of match[1].split(/\r?\n/)) {
    const field = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/);
    if (!field) continue;
    values[field[1]] = field[2].trim().replace(/^['"]|['"]$/g, '');
  }
  return values;
}

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  const files = [];
  for (const entry of entries) {
    const fullPath = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await markdownFiles(fullPath));
    else if (/\.mdx?$/.test(entry.name)) files.push(fullPath);
  }
  return files;
}

export async function validateContent(contentRoot) {
  const errors = [];
  const translations = new Map();

  for (const collection of COLLECTIONS) {
    for (const filename of await markdownFiles(resolve(contentRoot, collection))) {
      let data;
      try {
        data = parseFrontmatter(await readFile(filename, 'utf8'), filename);
      } catch (error) {
        errors.push(error.message);
        continue;
      }
      for (const key of ['title', 'description', 'locale', 'translationKey']) {
        if (!data[key]) errors.push(`${filename}: missing ${key}`);
      }
      if (data.locale && !REQUIRED_LOCALES.includes(data.locale)) errors.push(`${filename}: unsupported locale ${data.locale}`);
      if (data.translationKey && data.locale) {
        const key = `${collection}:${data.translationKey}`;
        const locales = translations.get(key) ?? new Set();
        locales.add(data.locale);
        translations.set(key, locales);
      }
    }
  }

  for (const [key, available] of translations) {
    const missing = REQUIRED_LOCALES.filter((locale) => !available.has(locale));
    if (missing.length) errors.push(`${key}: missing translation ${missing.join(', ')}`);
  }
  return errors;
}

const isDirectRun = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  const root = resolve(process.cwd(), 'src/content');
  const errors = await validateContent(root);
  if (errors.length) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log('Content validation passed.');
  }
}
