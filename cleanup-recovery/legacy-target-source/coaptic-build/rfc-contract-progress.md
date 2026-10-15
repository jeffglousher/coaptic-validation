Merged further RFC/contract fixes:
- #212: classic Block1/Block2 and BERT accept Size estimates; M controls completion, actual capacity still bounds bytes. Q-Block exact-size checks retained.
- #213: every received Q-Block payload requires stable Size1/Size2. Missing/changed sizes are refused before mutation; corrected continuation completes once.
- #214: Q-Block wire Request-Tag/nonempty ETag requirements, refusal before outgoing advancement, App ETag retention and changed representation refusal. Raw range APIs remain caller-managed; full recovery is still open.
- #215: response ETag/Location builders expose sticky typed validation errors instead of truncating/omitting invalid values; preserve empty Location segments; refuse before separate ACK/Observe side effects; release incoming body/RX state on error.

All four passed the full required local matrix and Linux CI/CodeQL before squash merge. Retained Linux process artifacts from CI runs 35482667517, 35482951306, 35483167594, 35483470366 qualify the existing process surface, not Q-Block/Observe conformance. Client metadata retention is the next PR; randomness, Echo/No-Response, full recovery and remaining audit coverage are still open.
