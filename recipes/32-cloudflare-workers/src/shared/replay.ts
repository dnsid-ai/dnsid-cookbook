import { DurableObject } from 'cloudflare:workers';

/**
 * Seen-nonce store. One instance per signer domain (idFromName), so checks for one agent
 * are serialized and strongly consistent. Rows expire after the signature freshness window.
 */
export class NonceStore extends DurableObject<object> {
  /** Creates the persistent nonce table if this instance has not initialized it yet. */
  constructor(ctx: DurableObjectState, env: object) {
    super(ctx, env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS seen (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
  }

  /**
   * Removes expired records and claims a nonce until expiresAtMs (Unix milliseconds).
   * Returns false when the nonce is already stored; callers supply its expiry.
   */
  async claim(nonce: string, expiresAtMs: number): Promise<boolean> {
    const now = Date.now();
    this.ctx.storage.sql.exec('DELETE FROM seen WHERE expires < ?', now);
    const fresh = this.ctx.storage.sql.exec('INSERT OR IGNORE INTO seen (nonce, expires) VALUES (?, ?)', nonce, expiresAtMs).rowsWritten > 0;
    return fresh;
  }
}
