// Fetch and WebIDL type names that @dnsid-ai/sdk 0.37.0's declarations (and structured-headers') use as globals. They
// come from the DOM library, which this Node project doesn't load; @types/node declares the same types without making
// these names global. Each is aliased to the type of Node's own implementation, so library checking stays on.
import type { BufferSource as NodeBufferSource } from 'node:stream/web';
import type {
  HeadersInit as NodeHeadersInit,
  RequestCredentials as NodeRequestCredentials,
  RequestInfo as NodeRequestInfo,
} from 'undici-types';

declare global {
  type BufferSource = NodeBufferSource;
  type HeadersInit = NodeHeadersInit;
  type RequestCredentials = NodeRequestCredentials;
  type RequestInfo = NodeRequestInfo;
}
