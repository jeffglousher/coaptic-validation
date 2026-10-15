RFC 8132 section 2.3.1 requires Content-Format on FETCH. App previously admitted a format-less fragmented selection and answered Continue. Reject missing format with 4.00 and malformed/repeated format with 4.02 before body admission or handler dispatch. The client returns FetchContentFormatRequired before allocating/sending/protecting a request.

Tests cover missing, overlong and repeated options; zero-valued Content-Format with both empty and nonempty selections; no handler effects/body slots on refusal; repeated local refusal without consuming capacity; authenticated protected errors and unchanged sender sequence on local refusal. Existing FETCH fixtures now carry the required format, and their exact Observe identity boundary includes that option. The missing-format regression failed before the change.

Validation at b84749d (rebased without content changes to c69b044): all 15 CONTRIBUTING checks and both two-iteration dogfood baselines passed on Windows MSVC; 614 all-feature library tests. Logs: D:\coaptic-build\fetch-format-validation-*.log. Hosted source-bound qualification is checked before merge. No full FETCH or independent-peer conformance claim.

Refs #201. Depends on #252.
