Protected oversized server notifications now use classic Block2 fallback, with a fresh Partial IV on the notification's first block. The fallback retains the active security context and preserves typed size/protocol errors; sequence exhaustion cannot become plaintext output.

The regression previously returned BufferTooSmall. Twelve cases cover NON/CON, 2,000/4,096/4,097-byte representations, first-send success/failure, retry cleanup, exact assembly, oversized refusal followed by a usable small notification, ACK cleanup and exhausted sender sequence. The fixture serves a stable representation on follow-ups. Changing-resource snapshot metadata, retained-final-block recovery and independent Observe interop remain open and are explicitly documented.

Validation at 4e51153: all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 638 all-feature library tests. Logs D:\coaptic-build\large-notify-validation-*.log. Hosted checks required before merge. No added retained state.

Refs #201. Depends on #268.
