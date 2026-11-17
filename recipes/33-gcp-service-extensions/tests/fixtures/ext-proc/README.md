# ext_proc fixtures

`request-headers-get.bin` is one serialized `envoy.service.ext_proc.v3.ProcessingRequest` carrying a GET request's
headers with `end_of_stream` true (271 bytes, SHA-256 `8bc5de965dccc5501f758856cc9189321047c75a64855fa01c2905bc181602f0`).

It was assembled by hand from the protobuf wire format (https://protobuf.dev/programming-guides/encoding/), with field
numbers read from the vendored `.proto` files, without the library the verifier uses. It was then decoded independently
by protoc 35.1 (the protobuf release Envoy v1.40.2 builds with; `protoc-35.1-linux-aarch_64.zip` from
https://github.com/protocolbuffers/protobuf/releases/tag/v35.1) against the same schema:

```
protoc -I proto -I <protoc>/include --decode=envoy.service.ext_proc.v3.ProcessingRequest \
  envoy/service/ext_proc/v3/external_processor.proto < tests/fixtures/ext-proc/request-headers-get.bin
```

Its output is `request-headers-get.protoc.txt`. The `x-empty` header's `raw_value` is written explicitly as an empty
value (`1a 00`); protoc's text format omits empty proto3 values, so that entry shows only its key.
