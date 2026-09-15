# DNSid Source Licenses

This file tracks Identity-Digital DNSid license provenance for repositories
represented by cookbook examples or docs.

## Repository Set

| Repository | Cookbook representation | Source commit | License copied |
| --- | --- | --- | --- |
| `dnsid-ai/dnsid-go` | Mentioned by `examples/plumbing-store/README.md` as the Go SDK upgrade path. | `efdfb2d0e7afe53a64ad45fa4b2a92490372519b` | `LICENSE.txt` |
| `dnsid-ai/dnsid` | Referenced by `recipes/06b-go-http-stripe/README.md` for the `dnsid` CLI and by `recipes/28-bedrock-agentcore-github-review/README.md` for related PR context. | `ba1a1a40d580bceb1aeca07876fee35ac800da40` | Not copied: no `LICENSE.TXT`, `LICENSE`, `COPYING`, or `NOTICE` file was present at the repository root. |

`dnsid-ai/dnsid-ts`, `dnsid-ai/dnsid-py`, and
`dnsid-ai/dnsid-docs` also have DNSid `LICENSE.TXT` files, but this
cookbook does not currently import, link, or name those repositories in its
examples or docs. They are not included here to avoid implying source
provenance that the cookbook does not use.

## Source Verification

- `dnsid-ai/dnsid-go/LICENSE.TXT` was copied from GitHub at the source
  commit above. The Git blob SHA was
  `122eaaf3df0e610b18d298865c0cbb99cd47c839`.
- `dnsid-ai/dnsid` was checked through the GitHub repository tree and a
  direct `LICENSE.TXT` contents lookup at the source commit above; no license
  file was available to copy.
