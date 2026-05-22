# stor HTTP/REST Protocol Binding — Plan

## Status: Stub

This document will define the HTTP/REST expression of the abstract `stor` federation protocol. See [`spec.md`](spec.md) for the protocol-agnostic specification that this binding must conform to.

## Planned contents

- URL structure and naming conventions
- HTTP method mapping for each operation defined in `spec.md §5`
- Request and response schemas (JSON)
- Authentication header conventions (Bearer token)
- Error response format and status code mapping
- Pagination header or body conventions
- Content-Type handling for asset delivery
- Node identity and public key discovery endpoint (analogous to Webfinger)
- Watermark signaling (how the client knows a watermark was applied)

## Notes

- FastAPI is a candidate framework for the reference implementation given the existing Python codebase.
- TLS termination via reverse proxy (nginx/caddy); the application layer assumes a secure transport.
- The node keypair (Ed25519) will be used to sign credentials and identify the node in federation.

## Reference

- Abstract spec: [`spec.md`](spec.md)
