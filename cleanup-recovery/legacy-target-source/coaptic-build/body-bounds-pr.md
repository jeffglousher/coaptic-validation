A custom Engine profile can assemble a representation larger than App's fixed 4-KiB response hold. App now completes that Call with typed ResponseBodyBounds instead of returning a truncated body as success. Cleanup retires the body, exchange and protected binding; public rustdoc describes the App/Engine boundary.

Regression proof failed before the fix. Classic and Q downloads test 4,095/4,096/4,097-byte representations on default and larger profiles, exact patterned bytes, no partial response, repeated refusal/reuse and unrelated-call preservation. Protected tests verify the same default-profile body boundary and 127/128/129-byte inline replies with explicit source-length/truncation metadata, binding cleanup and reuse. Default profile overflow remains BlockTransfer(Overflow); the larger Engine profile gets the App-specific failure.

Validation at 2bd4e91: all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 623 all-feature library tests. Logs D:\coaptic-build\body-bounds-validation-*.log. Hosted checks required before merge. This qualifies these fixed boundaries and ordinary download lifecycles, not all large Observe or compound soak behavior.

Refs #201, #202. Depends on #259.
