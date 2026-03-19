function decodeEscapes(input: string): string {
  return input
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeEntities(input: string): string {
  return input
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal) => String.fromCharCode(parseInt(decimal, 10)));
}

function stripWrappers(input: string): string {
  return input
    .replace(/```[^\n]*\n?([\s\S]*?)```/g, " $1 ")
    .replace(/`([^`]*)`/g, " $1 ")
    .replace(/<\/?[a-zA-Z][a-zA-Z0-9_-]{0,30}(?:\s[^>]{0,100})?>/g, " ");
}

function stripInvisible(input: string): string {
  return input.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u00AD\uFEFF]/g, "");
}

function normalizeWhitespace(input: string): string {
  return input.replace(/[\t\r\n]+/g, " ").replace(/\s{2,}/g, " ").trim();
}

export function canonicalize(input: string): string {
  return normalizeWhitespace(stripInvisible(stripWrappers(decodeEntities(decodeEscapes(input))))).toLowerCase();
}
