import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { validateContent } from '../scripts/validate-content.mjs';

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), 'faevault-content-'));
  for (const [name, source] of Object.entries(files)) {
    const filename = join(root, name);
    await mkdir(join(filename, '..'), { recursive: true });
    await writeFile(filename, source, 'utf8');
  }
  return root;
}

const article = (locale, key = 'first-guide') => `---
title: Example
description: Example description
locale: ${locale}
translationKey: ${key}
---
Body
`;

test('accepts a complete translation pair', async (t) => {
  const root = await fixture({
    'guides/zh-cn/example.md': article('zh-cn'),
    'guides/en/example.md': article('en'),
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.deepEqual(await validateContent(root), []);
});

test('reports a missing language counterpart', async (t) => {
  const root = await fixture({ 'stories/zh-cn/story.md': article('zh-cn', 'story-one') });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.match((await validateContent(root)).join('\n'), /missing translation en/);
});

test('reports required frontmatter fields', async (t) => {
  const root = await fixture({ 'legal/en/privacy.md': '---\nlocale: en\n---\nBody' });
  t.after(() => rm(root, { recursive: true, force: true }));
  const errors = (await validateContent(root)).join('\n');
  assert.match(errors, /missing title/);
  assert.match(errors, /missing translationKey/);
});
