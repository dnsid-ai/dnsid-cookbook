// The per-process trusted checkpoint store through request-bound access, driven by the SDK's own validated
// compare-and-swap path (`advanceTrustedC2spCheckpoint`): cancellation at the commit boundary, and stale or conflicting
// updates that must not overwrite accepted history.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, test } from 'node:test';

import {
  advanceTrustedC2spCheckpoint,
  C2spCheckpointConsistencyError,
  InMemoryTrustedC2spCheckpointStore,
  merkleRootFromEntries,
  MissingC2spConsistencyEvidenceError,
  parseC2spTlogLr,
  type Checkpoint,
  type IndexedEntry,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

import { RequestBoundCheckpointStore } from '../../src/identity.ts';

const reference = parseC2spTlogLr('c2sp-tlog:public:https://log-fixture.test#stream');
const ORIGIN = reference.origin;

function entries(count: number): IndexedEntry[] {
  return Array.from({ length: count }, (_, index) => ({ index, bytes: new Uint8Array(randomBytes(32)) }));
}

function checkpointOf(list: readonly IndexedEntry[], size = list.length): Checkpoint {
  return {
    origin: ORIGIN,
    treeSize: size,
    rootHash: merkleRootFromEntries(list.slice(0, size).map((entry) => entry.bytes)),
    signatures: [],
    signedText: '',
  };
}

const witnessed = () => new Date(Math.floor(Date.now() / 1000) * 1000);

async function advance(store: TrustedC2spCheckpointStore, list: readonly IndexedEntry[], size = list.length) {
  return advanceTrustedC2spCheckpoint(store, reference, checkpointOf(list, size), witnessed(), {
    completeEntries: list.slice(0, size),
  });
}

/**
 * A shared store that runs `before` inside compareAndSwap, after every caller-side check, just before the write, and
 * records each swap's result.
 */
function instrumented(
  shared: InMemoryTrustedC2spCheckpointStore,
  before: () => void | Promise<void>,
  results: boolean[] = [],
): TrustedC2spCheckpointStore {
  return {
    load: (origin, signal) => shared.load(origin, signal),
    async compareAndSwap(origin, expected, candidate, signal) {
      await before();
      const swapped = await shared.compareAndSwap(origin, expected, candidate, signal);
      results.push(swapped);
      return swapped;
    },
  };
}

describe('request-bound checkpoint store', () => {
  test('commits through the SDK path and returns defensive snapshots', async () => {
    const shared = new InMemoryTrustedC2spCheckpointStore();
    const request = new AbortController();
    const store = new RequestBoundCheckpointStore(shared, request.signal);
    const list = entries(2);
    const committed = await advance(store, list);
    assert.equal(committed.treeSize, 2);

    const loaded = (await store.load(ORIGIN)) as TrustedC2spCheckpoint;
    loaded.rootHash[0] = (loaded.rootHash[0] as number) ^ 0xff;
    committed.rootHash[1] = (committed.rootHash[1] as number) ^ 0xff;
    assert.deepEqual((await shared.load(ORIGIN))?.rootHash, checkpointOf(list).rootHash);
  });

  test('a request cancelled at the commit boundary writes nothing', async () => {
    const list = entries(3);
    const base = new InMemoryTrustedC2spCheckpointStore();
    await advance(base, list, 1);
    const request = new AbortController();
    // The request is cancelled inside compareAndSwap, after this wrapper's own check: only the request signal, carried
    // to the SDK store's commit, can stop the write now.
    const store = new RequestBoundCheckpointStore(instrumented(base, () => request.abort()), request.signal);
    await assert.rejects(advance(store, list, 3));
    assert.equal((await base.load(ORIGIN))?.treeSize, 1);
    assert.deepEqual((await base.load(ORIGIN))?.rootHash, checkpointOf(list, 1).rootHash);
  });

  test('a request already cancelled reads and writes nothing', async () => {
    const base = new InMemoryTrustedC2spCheckpointStore();
    let calls = 0;
    const counting: TrustedC2spCheckpointStore = {
      load: (origin, signal) => (calls++, base.load(origin, signal)),
      compareAndSwap: (...args) => (calls++, base.compareAndSwap(...args)),
    };
    const request = new AbortController();
    request.abort();
    const store = new RequestBoundCheckpointStore(counting, request.signal);
    await assert.rejects(store.load(ORIGIN));
    await assert.rejects(advance(store, entries(1)));
    assert.equal(calls, 0);
    assert.equal(await base.load(ORIGIN), undefined);
  });

  test('cancelling one request does not touch another request on the same shared store', async () => {
    const shared = new InMemoryTrustedC2spCheckpointStore();
    const first = new AbortController();
    const second = new AbortController();
    first.abort();
    await assert.rejects(advance(new RequestBoundCheckpointStore(shared, first.signal), entries(1)));
    const list = entries(2);
    assert.equal((await advance(new RequestBoundCheckpointStore(shared, second.signal), list)).treeSize, 2);
  });
});

describe('stale and conflicting updates cannot overwrite accepted history', () => {
  async function accepted(size: number) {
    const shared = new InMemoryTrustedC2spCheckpointStore();
    const list = entries(Math.max(size, 3));
    await advance(shared, list, size);
    const before = await shared.load(ORIGIN);
    const store = new RequestBoundCheckpointStore(shared, new AbortController().signal);
    return { shared, list, before, store };
  }

  test('a rollback to a smaller tree is refused', async () => {
    const { shared, list, before, store } = await accepted(3);
    await assert.rejects(advance(store, list, 2), (error: unknown) =>
      error instanceof C2spCheckpointConsistencyError && error.errorCategory === 'LOG_ROLLBACK',
    );
    assert.deepEqual(await shared.load(ORIGIN), before);
  });

  test('a different root at the same size (a fork) is refused', async () => {
    const { shared, before, store } = await accepted(2);
    await assert.rejects(advance(store, entries(2)), (error: unknown) =>
      error instanceof C2spCheckpointConsistencyError && error.errorCategory === 'LOG_FORK',
    );
    assert.deepEqual(await shared.load(ORIGIN), before);
  });

  test('a larger tree that does not extend the accepted one is refused', async () => {
    const { shared, before, store } = await accepted(2);
    await assert.rejects(advance(store, entries(3)), (error: unknown) =>
      error instanceof C2spCheckpointConsistencyError && error.errorCategory === 'LOG_INCONSISTENT',
    );
    assert.deepEqual(await shared.load(ORIGIN), before);
  });

  test('a larger tree with no consistency evidence is refused', async () => {
    const { shared, list, before, store } = await accepted(1);
    await assert.rejects(
      advanceTrustedC2spCheckpoint(store, reference, checkpointOf(list, 3), witnessed(), {}),
      MissingC2spConsistencyEvidenceError,
    );
    assert.deepEqual(await shared.load(ORIGIN), before);
  });

  /**
   * Two requests start from the same accepted checkpoint (size 1). The loser has verified its candidate and is held at
   * its commit while the winner commits size 3; then the loser is released into the SDK's compare-and-swap.
   */
  async function race(loserEntries: (shared: IndexedEntry[]) => { list: IndexedEntry[]; size: number }) {
    const shared = new InMemoryTrustedC2spCheckpointStore();
    const list = entries(3);
    await advance(shared, list, 1);
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reachedCommit = () => {};
    const atCommit = new Promise<void>((resolve) => {
      reachedCommit = resolve;
    });
    let commits = 0;
    const swaps: boolean[] = [];
    const slow = new RequestBoundCheckpointStore(
      instrumented(
        shared,
        async () => {
          if (commits++ > 0) return; // only the first attempt is held
          reachedCommit();
          await held;
        },
        swaps,
      ),
      new AbortController().signal,
    );
    const candidate = loserEntries(list);
    const losing = advance(slow, candidate.list, candidate.size).then(
      () => assert.fail('the stale or conflicting update was committed'),
      (error: unknown) => error,
    );
    await atCommit;
    const winner = new RequestBoundCheckpointStore(shared, new AbortController().signal);
    assert.equal((await advance(winner, list, 3)).treeSize, 3);
    release();
    const error = await losing;
    // The loser's swap found size 3, not the size 1 it verified against, and failed; the SDK reloaded, verified the
    // candidate again against size 3 and refused it there, without a second swap.
    assert.deepEqual(swaps, [false]);
    assert.equal((await shared.load(ORIGIN))?.treeSize, 3);
    assert.deepEqual((await shared.load(ORIGIN))?.rootHash, checkpointOf(list, 3).rootHash);
    return error;
  }

  test('a concurrent stale update loses the compare-and-swap, then its retry is refused as a rollback', async () => {
    const error = await race((list) => ({ list, size: 2 }));
    assert.ok(error instanceof C2spCheckpointConsistencyError && error.errorCategory === 'LOG_ROLLBACK', String(error));
  });

  test('a concurrent conflicting update (another tree of the same size) is refused as a fork', async () => {
    const error = await race((list) => ({ list: [list[0] as IndexedEntry, ...entries(3).slice(1)], size: 3 }));
    assert.ok(error instanceof C2spCheckpointConsistencyError && error.errorCategory === 'LOG_FORK', String(error));
  });
});
