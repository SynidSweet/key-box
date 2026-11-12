// KBOX-14: every failure of an Anthropic call is one of these fixed codes. The platform's own text (it may quote a key) is never carried.
export type AnthropicErrorCode = 'unreachable' | 'rejected' | 'http_error' | 'bad_answer' | 'ambiguous';

export class AnthropicError extends Error {
  readonly code: AnthropicErrorCode;

  constructor(code: AnthropicErrorCode) {
    super(`anthropic: ${code}`);
    this.name = 'AnthropicError';
    this.code = code;
  }
}
