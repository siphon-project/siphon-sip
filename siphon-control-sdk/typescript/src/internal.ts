/** Small internal utilities shared by the client, server, and SIP facade. */

/**
 * An unbounded, single-consumer async queue (the TypeScript analogue of Rust's
 * `tokio::sync::mpsc::unbounded_channel`). `push` never blocks; `next` resolves
 * with the next item, or `null` once the queue is closed and drained.
 */
export class AsyncQueue<T> {
  private readonly items: T[] = [];
  private readonly waiters: Array<(value: T | null) => void> = [];
  private closed = false;

  /** Enqueue an item (or hand it directly to a waiting consumer). */
  push(item: T): void {
    if (this.closed) {
      return;
    }
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter(item);
    } else {
      this.items.push(item);
    }
  }

  /** Await the next item, or `null` once the queue is closed and drained. */
  next(): Promise<T | null> {
    if (this.items.length > 0) {
      return Promise.resolve(this.items.shift() as T);
    }
    if (this.closed) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  /** Close the queue: pending and future `next()` calls resolve with `null`. */
  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) {
      waiter(null);
    }
  }

  /** Async-iterate the queue until it closes. */
  async *[Symbol.asyncIterator](): AsyncIterableIterator<T> {
    for (;;) {
      const item = await this.next();
      if (item === null) {
        return;
      }
      yield item;
    }
  }
}

/** A shared, mutable request-id counter (Rust's `Arc<AtomicU64>`). */
export interface IdCounter {
  value: number;
}

/** Resolve after `ms` milliseconds. */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
