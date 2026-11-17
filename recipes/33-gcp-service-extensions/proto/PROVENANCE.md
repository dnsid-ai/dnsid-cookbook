# Vendored ext_proc schema

The Envoy ext_proc service definition and every file it imports, byte for byte from pinned upstream commits. Nothing
here is edited or reduced. `node proto/vendor.mjs` re-creates the directory and `SHA256SUMS`; the unit tests check the
sums. Nothing is downloaded at run time.

| Files | Upstream | Pinned at | License |
|---|---|---|---|
| `envoy/**` | https://github.com/envoyproxy/envoy (`api/`) | tag `v1.40.2`, commit `b2d89e0ae53916f28770771fbdd49c5c99c5c5a2` | Apache-2.0 (`LICENSE.envoy`) |
| `xds/**`, `udpa/**` | https://github.com/cncf/xds | commit `ee656c7534f5d7dc23d44dd611689568f72017a6` (`xds` `0.0.0-20251210-ee656c7` in Envoy v1.40.2's `api/MODULE.bazel`) | Apache-2.0 (`LICENSE.xds`) |
| `validate/validate.proto` | https://github.com/bufbuild/protoc-gen-validate | tag `v1.3.3`, commit `92b9a7df69ca9f71bfc492f7a90adf4d36eab569` (`protoc-gen-validate` `1.3.3.envoy` in the same file) | Apache-2.0 (`LICENSE.protoc-gen-validate`) |
| `google/protobuf/*.proto` (any, descriptor, duration, struct, timestamp, wrappers) | not vendored: protobufjs `7.6.6` bundles the well-known types, and both protobufjs and `@grpc/proto-loader` `0.8.1` always use those copies | `package-lock.json` | BSD-3-Clause |

Entry point: `envoy/service/ext_proc/v3/external_processor.proto`. Documentation of the messages:
https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto and
https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto.
