import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
test('source routes preserve locale and canonical route', async () => {
  for (const locale of ['zh-cn', 'en']) {
    const route = await read(`src/pages/${locale}/source.astro`);
    assert.ok(route.includes(`locale="${locale}"`));
    assert.ok(route.includes('routePath="/source"'));
    assert.ok(route.includes('<SourcePage'));
  }
});
test('source page links to selected mirrors and base-aware archives', async () => {
  const source = await read('src/components/SourcePage.astro');
  assert.ok(source.includes('/tree/main/source-mirror/${platform}'));
  assert.ok(source.includes('withBaseAsset(`/source/faevault-${platform}-source.zip`)'));
  assert.ok(source.includes("withBaseAsset('/source/snapshot.json')"));
  assert.ok(source.includes('/source-mirror/OPEN_SOURCE_REVIEW.md'));
  assert.ok(source.includes('/source-mirror/LICENSE'));
  assert.ok(source.includes('full history repositories'));
  assert.ok(source.includes('真实保险库、凭据、签名密钥'));
  assert.ok(source.includes('Third-party source, dependencies and assets remain subject to their own licenses'));
});
test('header and footer both expose localized source navigation', async () => {
  const layout = await read('src/layouts/BaseLayout.astro');
  assert.equal((layout.match(/text\.nav\.source/g) || []).length, 2);
  const config = await read('src/i18n/config.ts');
  assert.ok(config.includes("source: '源码'"));
  assert.ok(config.includes("source: 'Source'"));
});
