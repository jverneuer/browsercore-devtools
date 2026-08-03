/**
 * Export helpers — serialize inspector output to JSON or a self-contained HTML
 * document. Dependency-free: no templating engine, no external assets.
 */

/** Stable, human-readable JSON (2-space indent). */
export function exportToJson(data: unknown): string {
    // JSON.stringify(undefined|Symbol) returns the undefined value, which would
    // violate the declared `: string` return type — coerce to "null" instead.
    return JSON.stringify(data, null, 2) ?? "null";
}

/** Escape a string for safe embedding in HTML text/attribute context. */
function escapeHtml(value: string): string {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

/** Render a single value to an HTML fragment (objects → sections, arrays → lists). */
function renderHtmlValue(value: unknown, label?: string): string {
    const labelPrefix = label === undefined ? "" : `${label}: `;
    const labelHeading = label === undefined ? "" : `<h2>${escapeHtml(label)}</h2>`;
    if (value === null || value === undefined) {
        return `<div class="row">${labelPrefix}<span class="null">null</span></div>`;
    }
    if (Array.isArray(value)) {
        const items = value
            .map((item) => `<li>${renderHtmlValue(item)}</li>`)
            .join("");
        return `<div class="section">${labelHeading}<ul>${items}</ul></div>`;
    }
    if (value instanceof Map) {
        const entries = Array.from<[string, unknown]>(value.entries());
        if (entries.length === 0) {
            return `<div class="section">${labelHeading}<span class="null">(empty)</span></div>`;
        }
        const rows = entries
            .map(([k, v]) => renderHtmlValue(v, k))
            .join("");
        return `<div class="section">${labelHeading}${rows}</div>`;
    }
    if (typeof value === "object") {
        const record = value as Record<string, unknown>;
        const keys = Object.keys(record);
        if (keys.length === 0) {
            return `<div class="section">${labelHeading}<span class="null">(empty)</span></div>`;
        }
        const rows = keys
            .map((key) => renderHtmlValue(record[key], key))
            .join("");
        return `<div class="section">${labelHeading}${rows}</div>`;
    }
    if (typeof value === "string") {
        return `<div class="row">${labelPrefix}<span class="str">"${escapeHtml(value)}"</span></div>`;
    }
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
        const className = typeof value === "number" || typeof value === "bigint" ? "num" : "bool";
        return `<div class="row">${labelPrefix}<span class="${className}">${value}</span></div>`;
    }
    // symbol / function / any residual object: serialize explicitly so nothing
    // falls back to Object's "[object Object]" stringification. Use String()
    // (not JSON.stringify) because JSON.stringify(Symbol|function) returns the
    // undefined value, which would make escapeHtml throw — String() renders
    // symbols as "Symbol(s)" and functions as their source string.
    return `<div class="row">${labelPrefix}<span class="any">${escapeHtml(String(value))}</span></div>`;
}

/**
 * Render `data` as a self-contained HTML document. Objects become sections with
 * labeled rows; arrays become lists; scalars are rendered inline.
 */
export function exportToHtml(title: string, data: unknown): string {
    const body = renderHtmlValue(data);
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
