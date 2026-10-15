Scan definite nested CBOR extension values iteratively with a single pending-item count and input-length bounds. Impossible container counts, malformed text and reserved two-byte simple encodings are refused. No auxiliary memory grows with nesting depth. This remains the documented definite-CBOR parser, not a complete RFC 9290 model or indefinite-CBOR decoder.

Proofs cover 100,000 nested map/array/tag groups, truncated nested data, overflowing declared counts, malformed UTF-8 and simple values, and corresponding valid byte strings/simple values/empty containers. CBOR validity reference: https://www.rfc-editor.org/rfc/rfc8949.html#section-3.3 . Existing seeded parser campaigns pass.

The no-default-features checks exposed test-only std imports; make them explicit and add alloc-only, OSCORE without std, alloc+OSCORE and std-only execution to CI and contributor checks. No library runtime dependency is added.

Local validation: all former 11 contributor checks plus all four additional feature combinations, seeded campaigns and all 16 pinned cross-target builds passed. 564 all-feature library unit tests passed. Code checked at aee9fb2; e4dce53 only adds the already-run CI commands/documentation. Source-bound cbor-bounds-seeded.json and cbor-bounds-cross-TARGET.json plus cbor-bounds-validation-*.log retained in D:\coaptic-build. Reviewed input/work bounds, parser behavior, portability, test isolation, documentation and evidence scope.

Advances #201/#202; broad conformance and coverage gaps remain open.
