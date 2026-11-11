// KBOX-14, KBOX-41: the seam by which a platform adapter tells core about a short-lived value it minted and injects (a
// Google access token). Core's scanner holds the value in every form it knows while the value lives, as it holds a stored one.
export interface MintedSink {
  /**
   * Registers `value` as held until `expiresAt` (milliseconds since the Unix epoch); after that it is dropped. A value the
   * scanner could not build forms of (empty, a NUL byte, under two bytes) is refused with a RangeError: it must not be injected.
   */
  add(keyref: string, value: Uint8Array, expiresAt: number): void;
}
