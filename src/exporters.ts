/**
 * Export helpers — serialize inspector output to JSON or a self-contained HTML
 * document. Dependency-free: no templating engine, no external assets.
 */

/** Stable, human-readable JSON (2-space indent). */
export function exportToJson(data: unknown): string {
    return JSON.stringify(data, null, 2);
}

/** Escape a string for safe embedding in HTML text/attribute context. */
function escapeHtml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/** Render a single value to an HTML fragment (objects → sections, arrays → lists). */
function renderHtmlValue(value: unknown, label: string | undefined): string {
    if (value === null || value === undefined) {
        return `<div class="row">${label !== undefined ? label + ": " : ""}<span class="null">null</span></div>`;
    }
    if (Array.isArray(value)) {
        const items = value
            .map((item) => `<li>${renderHtmlValue(item, undefined)}</li>`)
            .join("");
        return `<div class="section">${label !== undefined ? "<h2>" + escapeHtml(label) + "</h2>" : ""}<ul>${items}</ul></div>`;
    }
    if (value instanceof Map) {
        const entries = Array.from(value.entries());
        if (entries.length === 0) {
            return `<div class="section">${label !== undefined ? "<h2>" + escapeHtml(label) + "</h2>" : ""}<span class="null">(empty)</span></div>`;
        }
        const rows = entries
            .map(([k, v]) => renderHtmlValue(v, k))
            .join("");
        return `<div class="section">${label !== undefined ? "<h2>" + escapeHtml(label) + "</h2>" : ""}${rows}</div>`;
    }
    if (typeof value === "object") {
        const record = value as Record<string, unknown>;
        const keys = Object.keys(record);
        if (keys.length === 0) {
            return `<div class="section">${label !== undefined ? "<h2>" + escapeHtml(label) + "</h2>" : ""}<span class="null">(empty)</span></div>`;
        }
        const rows = keys
            .map((key) => renderHtmlValue(record[key], key))
            .join("");
        return `<div class="section">${label !== undefined ? "<h2>" + escapeHtml(label) + "</h2>" : ""}${rows}</div>`;
    }
    if (typeof value === "string") {
        return `<div class="row">${label !== undefined ? label + ": " : ""}<span class="str">"${escapeHtml(value)}"</span></div>`;
    }
    const className = typeof value === "number" ? "num" : "bool";
    return `<div class="row">${label !== undefined ? label + ": " : ""}<span class="${className}">${String(value)}</span></div>`;
}

/**
 * Render `data` as a self-contained HTML document. Objects become sections with
 * labeled rows; arrays become lists; scalars are rendered inline.
 */
export function exportToHtml(title: string, data: unknown): string {
    const body = renderHtmlValue(data, undefined);
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 1.5rem; color: #1a1a1a; }
  h1 { font-size: 1.1rem; border-bottom: 1px solid #ccc; padding-bottom: .25rem; }
  h2 { font-size: .95rem; margin: .75rem 0 .25rem; }
  .section { margin: .25rem 0; }
  .row { padding: .05rem 0; }
  ul { margin: .1rem 0; padding-left: 1.2rem; }
  .str { color: #0a7d2c; }
  .num { color: #1a4fbf; }
  .bool { color: #a04000; }
  .null { color: #888; font-style: italic; }
</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
${body}
</body>
</html>
`;
}
