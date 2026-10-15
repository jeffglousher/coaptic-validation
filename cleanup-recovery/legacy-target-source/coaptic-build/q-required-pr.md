RFC 9177 section 4.3 mandates 4.00 Bad Request when Q-Block1 lacks Request-Tag or Size1. App now rejects these before body admission or handler dispatch, retaining an existing partial transfer for a valid retry. Malformed/duplicate tags remain Bad Option; present empty Request-Tag and Size1=0 remain valid for an empty body.

Tests correct earlier error-code expectations and cover all presence combinations, exactly one handler effect for the valid case, no retained body on refusal, missing-size refusal during a partial upload followed by successful completion, and authenticated protected 4.00 responses for each missing field. No plaintext fallback is used.

Validation: all 15 CONTRIBUTING commands and both dogfood baseline checks passed locally at a2dc7e9 (585 all-feature library unit tests). Rebase onto merged #241 preserves the exact tree. Hosted checks provide separate cross-target and independent-process regression evidence.

This closes only the required-metadata response-code gap under #201. Q-Block1 acknowledgment/Continue timing, missing-block recovery and complete congestion/lifecycle qualification remain open.
