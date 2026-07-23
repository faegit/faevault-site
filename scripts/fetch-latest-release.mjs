import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = join(__dirname, "..", "src", "data", "latest-release.json");

async function main() {
  const res = await fetch(
    "https://api.github.com/repos/faegit/faevault-site/releases/latest",
    { headers: { Accept: "application/vnd.github+json" } }
  );
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  }
  const release = await res.json();
  const tag = release.tag_name;
  const version = tag.replace(/^v/, "");
  const baseUrl = `https://github.com/faegit/faevault-site/releases/download/${tag}`;
  const assets = {};
  for (const a of release.assets) {
    assets[a.name] = a.browser_download_url ?? `${baseUrl}/${a.name}`;
  }
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify({ tag, version, assets }, null, 2));
  console.log(`[fetch-latest-release] v${version} written to ${outPath}`);
}

main().catch((e) => {
  console.error("[fetch-latest-release] FAILED:", e.message);
  process.exit(1);
});
