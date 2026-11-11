// One message to the owner. Names only: a message never carries a key value (KBOX-2).
export interface Notice {
  /** Closed by the first unit that sends a notice. */
  readonly kind: string;
  readonly subject: string;
}

export interface Notifier {
  notify(notice: Notice): void;
}
