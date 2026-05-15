/**
 * Canonicalization utilities for normalizing untrusted text before rule
 * matching and downstream semantic classification.
 */

/** Options for canonicalization. */
export type CanonicalizeOptions = {
  /**
   * Unicode normalization form. Applied before other transformations.
   * NFC is recommended for security (canonical composition).
   * Default: "NFC"
   */
  normalization?: "NFC" | "NFD" | "NFKC" | "NFKD" | false;
  /**
   * Enable homoglyph detection. Replaces common lookalike characters
   * with their ASCII equivalents (e.g., Cyrillic 'а' → Latin 'a').
   * Default: false (disabled for backward compatibility)
   */
  detectHomoglyphs?: boolean;
};

/** Common homoglyph mappings for security-sensitive characters. */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  "\u0430": "a", // Cyrillic а
  "\u0435": "e", // Cyrillic е
  "\u043e": "o", // Cyrillic о
  "\u0440": "p", // Cyrillic р
  "\u0441": "c", // Cyrillic с
  "\u0443": "y", // Cyrillic у
  "\u0445": "x", // Cyrillic х
  // Greek lookalikes
  "\u0391": "A", // Greek Α
  "\u0392": "B", // Greek Β
  "\u0395": "E", // Greek Ε
  "\u0397": "H", // Greek Η
  "\u0399": "I", // Greek Ι
  "\u039a": "K", // Greek Κ
  "\u039c": "M", // Greek Μ
  "\u039d": "N", // Greek Ν
  "\u039f": "O", // Greek Ο
  "\u03a1": "P", // Greek Ρ
  "\u03a4": "T", // Greek Τ
  "\u03a5": "Y", // Greek Υ
  "\u03a7": "X", // Greek Χ
  // Fullwidth characters
  "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D", "\uff25": "E",
  "\uff26": "F", "\uff27": "G", "\uff28": "H", "\uff29": "I", "\uff2a": "J",
  "\uff2b": "K", "\uff2c": "L", "\uff2d": "M", "\uff2e": "N", "\uff2f": "O",
  "\uff30": "P", "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
  "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X", "\uff39": "Y",
  "\uff3a": "Z",
  "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d", "\uff45": "e",
  "\uff46": "f", "\uff47": "g", "\uff48": "h", "\uff49": "i", "\uff4a": "j",
  "\uff4b": "k", "\uff4c": "l", "\uff4d": "m", "\uff4e": "n", "\uff4f": "o",
  "\uff50": "p", "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
  "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x", "\uff59": "y",
  "\uff5a": "z",
};

function normalizeUnicode(input: string, form: "NFC" | "NFD" | "NFKC" | "NFKD"): string {
  return input.normalize(form);
}

function replaceHomoglyphs(input: string): string {
  let result = "";
  for (const char of input) {
    result += HOMOGLYPH_MAP[char] ?? char;
  }
  return result;
}

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

/** Normalizes text by decoding escapes/entities, stripping wrappers, and lowercasing. */
export function canonicalize(input: string, options?: CanonicalizeOptions): string {
  let result = input;
  
  // Apply Unicode normalization first (before any other transforms)
  const normalization = options?.normalization ?? "NFC";
  if (normalization !== false) {
    result = normalizeUnicode(result, normalization);
  }
  
  // Apply homoglyph detection if enabled
  if (options?.detectHomoglyphs) {
    result = replaceHomoglyphs(result);
  }
  
  return normalizeWhitespace(stripInvisible(stripWrappers(decodeEntities(decodeEscapes(result))))).toLowerCase();
}
