// KBOX-54 skeleton: the API of the forms library; the bodies come with the tests that need them.
export type FormName =
  | 'raw'
  | 'b64-0'
  | 'b64-1'
  | 'b64-2'
  | 'b64url-0'
  | 'b64url-1'
  | 'b64url-2'
  | 'hex'
  | 'HEX'
  | 'percent'
  | 'json'
  | 'json-slash'
  | 'u-lower'
  | 'u-upper';
export type CoreKind = 'written' | 'decoded';
export interface Form {
  readonly name: FormName;
  readonly core: CoreKind;
  readonly bytes: Uint8Array;
}
export type FormsFailure = 'empty' | 'short-core' | 'nul';
export type FormsResult = { readonly ok: true; readonly forms: readonly Form[] } | { readonly ok: false; readonly code: FormsFailure };
export interface ValueOptions {
  readonly prefix?: string;
}
export interface Match {
  readonly index: number;
  readonly name: FormName;
  readonly start: number;
  readonly end: number;
}
export interface Progress {
  readonly matches: readonly Match[];
  readonly releasable: number;
}
export interface Matcher {
  feed(chunk: Uint8Array): Progress;
  end(): Progress;
}
export interface StrippedView {
  readonly bytes: Uint8Array;
  readonly offsets: readonly number[];
}
const notBuilt = (): never => {
  throw new Error('not built');
};
export const coresOf = (_value: string, _options?: ValueOptions): readonly string[] => notBuilt();
export const scanForms = (_value: string, _options?: ValueOptions): FormsResult => notBuilt();
export const shareForms = (_value: string, _options?: ValueOptions): FormsResult => notBuilt();
export const strippedView = (_raw: Uint8Array): StrippedView => notBuilt();
export const createMatcher = (_forms: readonly Form[]): Matcher => notBuilt();
