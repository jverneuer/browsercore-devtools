// Copy vendored golden captures into dist/ so the bench command can read them
// at runtime via import.meta.dirname. tsc does not emit non-.ts files, so this
// post-build step mirrors src/bench/captures into dist/bench/captures.
import { cp, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src", "bench", "captures");
const dest = join(root, "dist", "bench", "captures");

await mkdir(dirname(dest), { recursive: true });
await cp(src, dest, { recursive: true });
