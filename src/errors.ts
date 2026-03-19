/** Error thrown when input exceeds the configured or default maximum length. */
export class InputTooLongError extends Error {
  /** The number of characters in the rejected input. */
  readonly length: number;
  /** The maximum allowed character count enforced for the input. */
  readonly maxLength: number;

  constructor(length: number, maxLength: number) {
    super(
      `Input length ${length} exceeds maximum allowed length of ${maxLength} characters. ` +
        `Truncate the input before classifying, or set maxInputLength: false in options (not recommended).`,
    );
    this.name = "InputTooLongError";
    this.length = length;
    this.maxLength = maxLength;
  }
}

/**
 * Resolves the effective max length and throws InputTooLongError if exceeded.
 * Pass the raw option value and the default; pass false to disable the guard.
 */
export function guardInputLength(text: string, maxLength: number | false | undefined, defaultMax: number): void {
  const max = maxLength === false ? false : (maxLength ?? defaultMax);
  if (max !== false && text.length > max) {
    throw new InputTooLongError(text.length, max);
  }
}
