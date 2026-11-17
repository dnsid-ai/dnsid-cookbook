// The callout's gRPC service: `envoy.service.ext_proc.v3.ExternalProcessor/Process`, a bidirectional stream, served
// over plaintext HTTP/2 (h2c) with @grpc/grpc-js. Each stream carries one request's headers from the load balancer and
// gets at most one `ProcessingResponse` back, from `processRequestHeaders` (src/callout.ts), then the stream ends.
//
// Byte-preserving method adapter. The method is registered with the vendored schema's path and streaming flags
// (`PROCESS_METHOD`), but NOT with its message (de)serializers: the request deserializer here only copies the received
// message bytes into a Buffer of their own, and the response serializer only hands over bytes that src/response.ts has
// already serialized and read back. The guarded decoder (`deserializeProcessingRequest`, src/ext-proc.ts) then runs
// once, inside `processRequestHeaders`, on the bytes exactly as received. Nothing decodes permissively and re-encodes a
// request before it is validated (that could erase a duplicate field, a conflicting oneof or invalid UTF-8), and no
// response is encoded twice. So a malformed message reaches the application and gets its own fixed 403.
//
// Per stream: one monotonic budget of VERIFICATION_BUDGET_MS from the moment the handler accepts the stream (covering
// waiting for the headers, decoding, verification, building the response and handing it to the transport), cut short
// by an earlier finite gRPC deadline from the caller, converted once to the monotonic clock. Neither is ever extended.
// The stream's own AbortController carries cancellation, disconnection, the deadline and shutdown into verification.
//
// What this service reports is local: a response "submitted" was handed to the HTTP/2 stream and the transport accepted
// the write. That is not confirmation that the load balancer received it, or that a request reached an origin. A failed
// stream (a message over the size limit, broken gRPC framing, a stopped or timed-out service) ends with a non-OK gRPC
// status or a reset, never one of the application's responses; at the load balancer that is its own 500 (decision
// D-05), which local tests can't show.
//
// A submitted response that the transport does not accept in time (the peer stopped reading, so HTTP/2 flow control
// holds the bytes), or whose write fails, is retracted: the stream's HTTP/2 stream is reset (RST_STREAM CANCEL), which
// discards the queued bytes, so the response can't be delivered later. Ending the gRPC call is not enough: grpc-js
// sends its status only after the pending write completes, so the response would still go out once the peer reads.
// grpc-js 1.14.7 has no public way to reset a call's HTTP/2 stream; see `http2StreamOf`.

import { randomUUID } from 'node:crypto';
import { constants as http2Constants } from 'node:http2';

import { Server, ServerCredentials, status, type ServerDuplexStream, type ServiceDefinition } from '@grpc/grpc-js';

import { processRequestHeaders, type CalloutObserver } from './callout.ts';
import { PROCESS_METHOD } from './ext-proc.ts';
import type { VerificationRuntime } from './identity.ts';
import { denialResponse, MAX_RESPONSE_BYTES, type CalloutResponse, type ResponseReason, type VerifiedSummary } from './response.ts';

/** Each stream's budget, under the authorization extension's 3,000 ms timeout (decision D-13). */
export const VERIFICATION_BUDGET_MS = 2_500;
/**
 * The largest request message accepted, in bytes. Google documents a 128 kB limit for callout response messages and
 * none for requests on its callout overview; a request-headers message carries only a request's headers, so this
 * mirrors that bound. A larger message is refused by the gRPC layer (RESOURCE_EXHAUSTED) and never reaches the
 * application. grpc-js would otherwise accept 4 MiB.
 */
export const MAX_REQUEST_MESSAGE_BYTES = 131_072;
/**
 * The largest response message sent, in bytes: the response layer's own bound (MAX_RESPONSE_BYTES, 16,384), far under
 * Google's 128 kB response limit. The response layer never builds a larger one; this is the transport's second check.
 */
export const MAX_RESPONSE_MESSAGE_BYTES = MAX_RESPONSE_BYTES;
/**
 * How long shutdown lets active streams finish before it cancels them and closes every connection. Longer than one
 * budget, so a stream accepted before shutdown normally ends on its own; well within the 10 s Cloud Run allows after
 * SIGTERM.
 */
export const SHUTDOWN_GRACE_MS = 3_000;
/** How long a submitted response may wait for the transport to accept the write before the stream counts as failed. */
export const SUBMIT_SETTLE_MS = 1_000;
/**
 * grpc-js ends a stream at the caller's deadline on its own wall-clock timer; a cancellation this close to the
 * converted deadline (or after it) is attributed to the deadline.
 */
const CLIENT_DEADLINE_TOLERANCE_MS = 25;

const SERVER_OPTIONS = Object.freeze({
  'grpc.max_receive_message_length': MAX_REQUEST_MESSAGE_BYTES,
  'grpc.max_send_message_length': MAX_RESPONSE_MESSAGE_BYTES,
});

// ---------- the byte-preserving method adapter ----------

/** The received message's bytes, copied, so nothing else holds or changes them. Never decodes. */
function copyMessageBytes(data: Buffer): Buffer {
  return Buffer.from(data);
}

/** A response the response layer already serialized and checked; anything else is refused, never encoded. */
function submitResponseBytes(value: unknown): Buffer {
  if (!Buffer.isBuffer(value) || value.length === 0 || value.length > MAX_RESPONSE_MESSAGE_BYTES) {
    throw new TypeError('not a serialized ProcessingResponse');
  }
  return value;
}

function requestBytes(value: unknown): Buffer {
  if (!Buffer.isBuffer(value)) throw new TypeError('not a serialized ProcessingRequest');
  return value;
}

/**
 * `ExternalProcessor/Process` with the vendored path and streaming flags, and byte-preserving (de)serializers in place of
 * the schema's: see the adapter note at the top of this file.
 */
export const PROCESS_BYTES_SERVICE = Object.freeze({
  Process: Object.freeze({
    path: PROCESS_METHOD.path,
    requestStream: PROCESS_METHOD.requestStream,
    responseStream: PROCESS_METHOD.responseStream,
    // Used only by clients; the service never serializes a request. Bytes go out as they are.
    requestSerialize: requestBytes,
    requestDeserialize: copyMessageBytes,
    responseSerialize: submitResponseBytes,
    responseDeserialize: copyMessageBytes,
  }),
}) satisfies ServiceDefinition;

if (!PROCESS_BYTES_SERVICE.Process.requestStream || !PROCESS_BYTES_SERVICE.Process.responseStream) {
  throw new Error('ExternalProcessor/Process is not a bidirectional stream in the vendored schema');
}

// ---------- the call's HTTP/2 stream ----------

/** The part of a node:http2 server stream this service uses: closing it with a code sends RST_STREAM. */
interface ResettableStream {
  readonly closed: boolean;
  readonly destroyed: boolean;
  close(code: number): void;
}

/**
 * The HTTP/2 stream under a grpc-js 1.14.7 server call (pinned exactly in package.json). Not public API: the server
 * stream holds its call as `call`, and with no server interceptors that is grpc-js's base call, which holds the node:http2
 * stream as `stream`. Checked on every stream; when the shape isn't there (another grpc-js version), the stream is refused
 * before verification, so no response is ever submitted that couldn't be retracted. Exported for its tests.
 */
export function http2StreamOf(call: ServerDuplexStream<Buffer, Buffer>): ResettableStream | undefined {
  const base = (call as unknown as { call?: { stream?: unknown } }).call;
  const stream = base?.stream as Partial<ResettableStream> | undefined;
  if (
    typeof stream !== 'object' ||
    stream === null ||
    stream.constructor?.name !== 'ServerHttp2Stream' ||
    typeof stream.close !== 'function' ||
    typeof stream.closed !== 'boolean' ||
    typeof stream.destroyed !== 'boolean'
  ) {
    return undefined;
  }
  return stream as ResettableStream;
}

// ---------- terminal records ----------

export type TerminalOutcome =
  | 'continue_submitted' // the continuation was handed to the transport and the write accepted (not delivery)
  | 'deny_submitted' // a 403 was handed to the transport and the write accepted (not delivery)
  | 'cancelled' // the caller cancelled or disconnected before a response was submitted
  | 'client_deadline_exceeded' // the caller's own, earlier gRPC deadline ended the stream; nothing was submitted
  | 'shutdown' // the service shut down and cancelled the stream; nothing was submitted
  | 'idle_timeout' // no request message arrived within the budget
  | 'empty_stream' // the caller closed its side without sending a message
  | 'transport_failed' // a response was submitted, but the stream failed or closed before the write was accepted; the stream was reset
  | 'stream_error'; // the stream failed before a response was submitted

/**
 * One per stream the service handled, written when the stream reaches its terminal state. Bounded and fixed-shape:
 * never request headers, signatures, metadata, paths or query strings, keys, SDK objects, checkpoints or error text.
 */
export interface TerminalRecord {
  readonly severity: 'INFO' | 'WARNING';
  readonly event: 'ext_proc_stream';
  /** Generated locally per stream; correlates nothing outside this process. */
  readonly id: string;
  readonly outcome: TerminalOutcome;
  /** The 403's reason code: for `deny_submitted`, and for a `transport_failed` denial. */
  readonly reason?: ResponseReason;
  /** For `transport_failed`: which response was submitted. */
  readonly attempted?: 'continue' | 'deny';
  /** From acceptance of the stream to its terminal state, whole ms on the monotonic clock. */
  readonly elapsedMs: number;
  /** For `continue_submitted` only: from the verification result, never from the request. */
  readonly verified?: VerifiedSummary;
}

export type LogSink = (record: TerminalRecord) => void;

/** Production logging: one JSON line per record on stdout, which Cloud Run reads as a structured log entry. */
export const stdoutLogSink: LogSink = (record) => {
  process.stdout.write(`${JSON.stringify(record)}\n`);
};

// ---------- the service ----------

/** Test hooks, for orderings real sockets can't schedule reliably. Never set in production. */
export interface ServiceHooks {
  /** The handler accepted a stream. */
  accepted?(id: string, call: ServerDuplexStream<Buffer, Buffer>): void;
  /** Verification hooks for one stream. */
  observer?(id: string): CalloutObserver | undefined;
  /** A response is about to go through the final checks (stream state, cancellation, deadline) and be submitted. */
  beforeSubmit?(id: string, call: ServerDuplexStream<Buffer, Buffer>): void;
  /** The response was written and the stream ended locally; the transport hasn't confirmed the write yet. */
  afterSubmit?(id: string, call: ServerDuplexStream<Buffer, Buffer>): void;
  /** The stream's HTTP/2 stream is about to be reset, retracting a submitted response (or closing a closed stream). */
  beforeReset?(id: string): void;
}

export interface CalloutServiceOptions {
  /** The verification runtime: governance policy, backend, the shared checkpoint store and material cache. */
  readonly runtime: VerificationRuntime;
  readonly log?: LogSink;
  /** Defaults to VERIFICATION_BUDGET_MS; a test may shorten it. */
  readonly budgetMs?: number;
  /** Defaults to SHUTDOWN_GRACE_MS. */
  readonly shutdownGraceMs?: number;
  /** Defaults to SUBMIT_SETTLE_MS; a test may shorten it. */
  readonly submitSettleMs?: number;
  readonly hooks?: ServiceHooks;
  /**
   * The deployment's attestation key (src/attestation.ts): every continuation then also sets `x-dnsid-attestation`.
   * The executable always gives one (src/main.ts); without one, Demo Bank refuses every request.
   */
  readonly attestationKey?: Uint8Array;
}

export interface CalloutService {
  /** Binds plaintext HTTP/2 on `host:port` (port 0: an ephemeral port) and resolves to the bound port. */
  listen(host: string, port: number): Promise<number>;
  /**
   * Stops accepting streams and connections, lets active streams finish for the grace period, then cancels what is
   * left (cancellation reaches verification) and closes every connection. Resolves once closed; idempotent.
   */
  shutdown(): Promise<void>;
  /** Streams accepted and not yet in their terminal state. */
  readonly activeStreams: number;
}

/** A bind failure, with a fixed message: no address or system error text. */
export class ServiceListenError extends Error {
  constructor() {
    super('the callout service could not listen on the configured port');
    this.name = 'ServiceListenError';
  }
}

function positiveMs(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be a positive number of ms`);
  return value;
}

interface ServiceState {
  readonly runtime: VerificationRuntime;
  readonly log: LogSink;
  readonly budgetMs: number;
  readonly settleMs: number;
  readonly hooks: ServiceHooks;
  readonly attestationKey: Uint8Array | undefined;
  readonly active: Set<ProcessStream>;
  shuttingDown: boolean;
  forced: boolean;
}

/** Builds the service. Starts no listener: `listen` does. */
export function createCalloutService(options: CalloutServiceOptions): CalloutService {
  const runtime = options?.runtime;
  if (runtime?.backend === undefined || runtime.checkpointStore === undefined) {
    throw new TypeError('the callout service requires a verification runtime');
  }
  const key = options.attestationKey;
  if (key !== undefined && (!(key instanceof Uint8Array) || key.length < 32)) throw new TypeError('attestationKey must be at least 32 bytes');
  const state: ServiceState = {
    runtime,
    log: options.log ?? stdoutLogSink,
    budgetMs: positiveMs(options.budgetMs, VERIFICATION_BUDGET_MS, 'budgetMs'),
    settleMs: positiveMs(options.submitSettleMs, SUBMIT_SETTLE_MS, 'submitSettleMs'),
    hooks: options.hooks ?? {},
    attestationKey: key === undefined ? undefined : Buffer.from(key),
    active: new Set(),
    shuttingDown: false,
    forced: false,
  };
  const graceMs = positiveMs(options.shutdownGraceMs, SHUTDOWN_GRACE_MS, 'shutdownGraceMs');
  const server = new Server(SERVER_OPTIONS);
  server.addService(PROCESS_BYTES_SERVICE, {
    Process(call: ServerDuplexStream<Buffer, Buffer>) {
      new ProcessStream(state, call).start();
    },
  });
  let closing: Promise<void> | undefined;

  return {
    listen(host, port) {
      if (state.shuttingDown) return Promise.reject(new ServiceListenError());
      return new Promise((resolve, reject) => {
        try {
          server.bindAsync(`${host}:${port}`, ServerCredentials.createInsecure(), (error, bound) => {
            if (error !== null) reject(new ServiceListenError());
            else resolve(bound);
          });
        } catch {
          reject(new ServiceListenError());
        }
      });
    },
    shutdown() {
      closing ??= new Promise<void>((resolve) => {
        state.shuttingDown = true;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(grace);
          resolve();
        };
        const grace = setTimeout(() => {
          state.forced = true;
          for (const stream of [...state.active]) stream.abortForShutdown();
          server.forceShutdown();
          finish();
        }, graceMs);
        server.tryShutdown(finish);
      });
      return closing;
    },
    get activeStreams() {
      return state.active.size;
    },
  };
}

// ---------- one stream ----------

type Phase = 'awaiting_headers' | 'verifying' | 'submitting' | 'ended';

/** The reason a stream's verification is aborted: the stream reached its terminal state or submitted its response. */
class StreamEnded extends Error {
  constructor() {
    super('the stream ended');
    this.name = 'StreamEnded';
  }
}

/**
 * The state machine of one `Process` stream. Verification starts on the first message, without waiting for the caller
 * to close its side; a normal half-close afterwards changes nothing. At most one response is written, then the stream
 * ends. Every event after the terminal state is ignored.
 */
class ProcessStream {
  readonly #id = randomUUID();
  readonly #state: ServiceState;
  readonly #call: ServerDuplexStream<Buffer, Buffer>;
  readonly #controller = new AbortController();
  #http2: ResettableStream | undefined;
  #phase: Phase = 'awaiting_headers';
  #accepted = 0;
  #deadline = 0;
  #deadlineSource: 'application' | 'client' = 'application';
  #clientDeadline = Number.POSITIVE_INFINITY;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #settleTimer: ReturnType<typeof setTimeout> | undefined;
  #submitted: CalloutResponse | undefined;

  readonly #onData = (message: unknown) => this.#message(message);
  readonly #onEnd = () => this.#halfClosed();
  readonly #onCancelled = () => this.#cancelled();
  readonly #onError = () => this.#streamError();

  constructor(state: ServiceState, call: ServerDuplexStream<Buffer, Buffer>) {
    this.#state = state;
    this.#call = call;
  }

  start(): void {
    this.#accepted = performance.now();
    this.#state.active.add(this);
    try {
      const appDeadline = this.#accepted + this.#state.budgetMs;
      // The caller's deadline, as grpc-js read it from `grpc-timeout` (wall clock), converted once to the monotonic clock.
      const wall = this.#call.getDeadline();
      const wallMs = wall instanceof Date ? wall.getTime() : wall;
      if (Number.isFinite(wallMs)) this.#clientDeadline = this.#accepted + (wallMs - Date.now());
      this.#deadline = Math.min(appDeadline, this.#clientDeadline);
      if (this.#clientDeadline < appDeadline) this.#deadlineSource = 'client';
      this.#call.on('data', this.#onData);
      this.#call.on('end', this.#onEnd);
      this.#call.on('cancelled', this.#onCancelled);
      this.#call.on('error', this.#onError);
      this.#http2 = http2StreamOf(this.#call);
      this.#timer = setTimeout(() => this.#deadlineReached(), Math.max(0, Math.ceil(this.#deadline - performance.now())));
      this.#state.hooks.accepted?.(this.#id, this.#call);
      if (this.#state.shuttingDown) {
        this.#endWithStatus('shutdown', status.UNAVAILABLE, 'shutting down');
        return;
      }
      if (this.#http2 === undefined) {
        // No way to retract a response on this stream: refuse it before verification.
        this.#endWithStatus('stream_error', status.INTERNAL, 'stream setup failed');
        return;
      }
      if (this.#call.cancelled) this.#cancelled();
    } catch {
      this.#endWithStatus('stream_error', status.INTERNAL, 'stream setup failed');
    }
  }

  #message(message: unknown): void {
    if (this.#phase === 'awaiting_headers') {
      this.#phase = 'verifying';
      this.#verify(message);
      return;
    }
    if (this.#phase === 'verifying') {
      // Only one request's headers belong on this stream. The first operation is abandoned (submission aborts it) and
      // the stream fails closed.
      this.#submit(denialResponse('unexpected_message'));
    }
    // After a response was submitted, or the stream ended: never another verification or reply.
  }

  #verify(message: unknown): void {
    const bytes = Buffer.isBuffer(message) ? message : Buffer.alloc(0);
    let observer: CalloutObserver | undefined;
    try {
      observer = this.#state.hooks.observer?.(this.#id);
    } catch {
      observer = undefined;
    }
    const key = this.#state.attestationKey;
    const context = { runtime: this.#state.runtime, signal: this.#controller.signal, deadline: this.#deadline, ...(key === undefined ? {} : { attestationKey: key }) };
    processRequestHeaders(bytes, context, observer).then(
      (result) => this.#decided(result),
      () => this.#decided(denialResponse('internal_error')),
    );
  }

  #decided(result: CalloutResponse): void {
    // A completion after the stream moved on (a second message, the deadline, cancellation) is ignored.
    if (this.#phase !== 'verifying') return;
    this.#submit(result);
  }

  /** The stream can still take a response: not cancelled, destroyed or already ended. */
  #transportOpen(): boolean {
    const call = this.#call;
    return !call.cancelled && !call.destroyed && !call.writableEnded;
  }

  /**
   * The final checks and the write, with nothing awaited in between: the stream must still be open, and the original
   * deadline not reached. A response past an application budget becomes the budget 403 if the stream can still take
   * it; past the caller's own deadline, nothing is written.
   */
  #submit(chosen: CalloutResponse): void {
    if (this.#phase === 'submitting' || this.#phase === 'ended') return;
    try {
      this.#state.hooks.beforeSubmit?.(this.#id, this.#call);
    } catch {
      // a test hook's failure changes nothing
    }
    let response = chosen;
    if (!this.#transportOpen()) {
      this.#end(this.#closedOutcome());
      this.#reset();
      return;
    }
    if (performance.now() >= this.#deadline) {
      if (this.#deadlineSource === 'client') {
        this.#endWithStatus('client_deadline_exceeded', status.DEADLINE_EXCEEDED, 'deadline exceeded');
        return;
      }
      response = denialResponse('verification_budget_exhausted');
    }
    this.#phase = 'submitting';
    this.#submitted = response;
    // Whatever verification is still running is abandoned: its completion, if any, is ignored.
    if (!this.#controller.signal.aborted) this.#controller.abort(new StreamEnded());
    try {
      this.#call.write(response.response, (error: Error | null | undefined) => this.#written(error));
      this.#call.end();
    } catch {
      this.#end('transport_failed');
      return;
    }
    clearTimeout(this.#timer);
    // A write the transport hasn't accepted by then is retracted (#end resets the stream): see the note at the top.
    this.#settleTimer = setTimeout(() => this.#end('transport_failed'), this.#state.settleMs);
    try {
      this.#state.hooks.afterSubmit?.(this.#id, this.#call);
    } catch {
      // as above
    }
  }

  #written(error: Error | null | undefined): void {
    if (this.#phase !== 'submitting') return;
    if (error !== null && error !== undefined) {
      this.#end('transport_failed');
      return;
    }
    this.#end(this.#submitted?.decision === 'continue' ? 'continue_submitted' : 'deny_submitted');
  }

  #halfClosed(): void {
    // A normal half-close after the message changes nothing; only a stream that sent nothing ends here.
    if (this.#phase === 'awaiting_headers') this.#endWithStatus('empty_stream', status.INVALID_ARGUMENT, 'no request headers message');
  }

  #closedOutcome(): TerminalOutcome {
    if (this.#state.forced) return 'shutdown';
    if (performance.now() >= this.#clientDeadline - CLIENT_DEADLINE_TOLERANCE_MS) return 'client_deadline_exceeded';
    return 'cancelled';
  }

  #cancelled(): void {
    if (this.#phase === 'ended') return;
    this.#end(this.#phase === 'submitting' ? 'transport_failed' : this.#closedOutcome());
  }

  #streamError(): void {
    if (this.#phase === 'ended') return;
    this.#end(this.#phase === 'submitting' ? 'transport_failed' : 'stream_error');
  }

  #deadlineReached(): void {
    if (this.#phase === 'awaiting_headers') {
      if (this.#deadlineSource === 'client') this.#endWithStatus('client_deadline_exceeded', status.DEADLINE_EXCEEDED, 'deadline exceeded');
      else this.#endWithStatus('idle_timeout', status.DEADLINE_EXCEEDED, 'no request headers message within the budget');
      return;
    }
    if (this.#phase !== 'verifying') return;
    if (this.#deadlineSource === 'client') {
      this.#endWithStatus('client_deadline_exceeded', status.DEADLINE_EXCEEDED, 'deadline exceeded');
      return;
    }
    // The verification is abandoned; the stream, if still open, gets the budget 403.
    this.#submit(denialResponse('verification_budget_exhausted'));
  }

  /** Shutdown's grace period ran out: cancel verification and end without a response; the connection closes next. */
  abortForShutdown(): void {
    if (this.#phase === 'ended') return;
    this.#end(this.#phase === 'submitting' ? 'transport_failed' : 'shutdown');
  }

  /** Ends the stream with a non-OK gRPC status and no response message. */
  #endWithStatus(outcome: TerminalOutcome, code: status, details: string): void {
    if (this.#phase === 'ended') return;
    this.#end(outcome);
    if (!this.#transportOpen()) {
      // No status can be sent on it any more; make sure the HTTP/2 stream itself is closed too.
      this.#reset();
      return;
    }
    try {
      // grpc-js turns an 'error' event on a server stream into the stream's status and ends it.
      this.#call.emit('error', Object.assign(new Error(details), { code, details }));
    } catch {
      // the stream is already closing
    }
  }

  /**
   * The terminal state, once: timers cleared, listeners removed, verification cancelled (this, and submission, are where
   * cancellation, disconnection, deadlines and shutdown reach the verification), a submitted response that wasn't
   * accepted retracted (the HTTP/2 stream reset), then one record.
   */
  #end(outcome: TerminalOutcome): void {
    if (this.#phase === 'ended') return;
    const attempted = this.#phase === 'submitting' ? this.#submitted : undefined;
    const retract = attempted !== undefined && outcome !== 'continue_submitted' && outcome !== 'deny_submitted';
    this.#phase = 'ended';
    clearTimeout(this.#timer);
    clearTimeout(this.#settleTimer);
    if (!this.#controller.signal.aborted) this.#controller.abort(new StreamEnded());
    const call = this.#call;
    call.off('data', this.#onData);
    call.off('end', this.#onEnd);
    call.off('cancelled', this.#onCancelled);
    call.off('error', this.#onError);
    // Late messages are read and dropped; grpc-js keeps its own 'error' listener, so nothing goes unhandled.
    call.on('data', () => {});
    // Before the record, and with nothing awaited: once the stream is reset, its queued response can't be delivered.
    if (retract) this.#reset();
    this.#state.active.delete(this);
    this.#record(outcome, attempted);
  }

  /**
   * Resets the stream's HTTP/2 stream with RST_STREAM CANCEL, unless it is already closed. Bytes still queued on it
   * (a response held by flow control) are discarded; the peer sees the stream cancelled, and the connection's other
   * streams carry on. grpc-js then reports the call cancelled, which this stream, having ended, ignores.
   */
  #reset(): void {
    try {
      this.#state.hooks.beforeReset?.(this.#id);
    } catch {
      // a test hook's failure changes nothing
    }
    const stream = this.#http2;
    if (stream === undefined || stream.closed || stream.destroyed) return;
    try {
      stream.close(http2Constants.NGHTTP2_CANCEL);
    } catch {
      // already closing
    }
  }

  #record(outcome: TerminalOutcome, attempted: CalloutResponse | undefined): void {
    let record: TerminalRecord;
    try {
      const base = {
        severity: outcome === 'continue_submitted' || outcome === 'deny_submitted' ? 'INFO' : 'WARNING',
        event: 'ext_proc_stream',
        id: this.#id,
        outcome,
      } as const;
      const elapsedMs = Math.max(0, Math.round(performance.now() - this.#accepted));
      if (outcome === 'continue_submitted' && attempted?.decision === 'continue') {
        record = { ...base, elapsedMs, verified: Object.freeze({ ...attempted.verified }) };
      } else if (outcome === 'deny_submitted' && attempted?.decision === 'deny') {
        record = { ...base, reason: attempted.reason, elapsedMs };
      } else if (outcome === 'transport_failed' && attempted !== undefined) {
        record =
          attempted.decision === 'deny'
            ? { ...base, attempted: 'deny', reason: attempted.reason, elapsedMs }
            : { ...base, attempted: 'continue', elapsedMs };
      } else {
        record = { ...base, elapsedMs };
      }
      const result: unknown = this.#state.log(Object.freeze(record));
      if (result instanceof Promise) result.catch(() => {});
    } catch {
      // A logging failure changes nothing about the stream: its response, if any, is already submitted.
    }
  }
}
