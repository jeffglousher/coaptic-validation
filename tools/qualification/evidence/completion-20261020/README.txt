Coaptic current baseline evidence — 2026-10-20

This bundle is the core 75548536d6ea417dc3f4a74c7fc9fc4e03ab5953 baseline,
with Windows/device suite ccb41104a138876f59527cfb2414f7bfa102e663 (same tree
as merged 971f4d7612d7c727f17bb64d62936be195565a43). The Linux fixture has
its separately named ea242dc5bdf430c779ec7c2086d336fba93955e2 suite at the
same core; its exact source must not be relabeled. Nothing here qualifies newer
receipt-reconciliation/read-campaign code or firmware.

manifest.json hashes every other file (SHA-256 and byte length). Original
Linux/Windows evidence files remain byte-identical. esp32-baseline.json names
exact source/tree/artifact digests, migration and normal run IDs, configuration,
projections and limits. Inspect excerpts contain only the exact selected-device
public lines; their original log digests are retained. normal-runtime-public.jsonl
retains verbatim numeric/API lifecycle records with no application payload.
Private firmware, configurations, keys, NVS bytes and DPAPI ciphertext are absent.
The already-public revision 1–8 custody chain/provenance remains linked in PR123.

Installed execution: one-time reviewed initialization then permit-disabled normal
firmware; identity/key/owner/echo grant/revision 8 remain unchanged across three
Inspect reads and a normal read/reset. Normal OTA 22.08s; protected 45-byte echo
recovers from authenticated 5.03/Max-Age 1 to same-session 2.05. The original
host receipt journal was explicitly initialized; no new installed effect exists.

Memory accounting: exact ELF-managed owner 29,184B is nested in the 49,464B
worker future, inside the existing 196,608B worker stack; Runtime metadata104B
also lies on that stack. Observed worker used high-water is175,700B. These are
overlapping categories, not an additive stack peak. Linker shared D/IRAM100,519B
and dedicated IRAM16,384B are separate; mapped flash2,226,064B is separate from
the linker image estimate2,314,823B and actual OTA bytes2,314,976B. No PSRAM is
configured. Other linker banks retain32B RTC-slow static and24B RTC-fast reserved
storage, outside the size tool's main D/IRAM summary. No fabricated grand total
or comparative improvement is asserted.

SDK heap samples distinguish payload allocations from total-minus-free nonfree
space (which includes allocator overhead). Internal8-bit: payload max289,064B,
nonfree max294,100B, free min67,728B; all8-bit: payload max293,312B, nonfree
max298,372B, free min63,456B. Total reported capacity361,828B is unchanged in
the retained samples. The319,056B total-minus-summed-region-low-water envelope
can combine different times/regions and is not a simultaneous whole-system peak.
Capability rows overlap and are sequential; do not add them. Dynamic task stacks,
TCBs, sockets and runtime allocations already contribute to SDK heap accounting.
normal-heap-domains.json checks the primary SDK against retained normal sections:
the only possible standard non8-bit/EXEC-only region is fully occupied by normal
static IRAM code; no additional allocatable standard heap domain is omitted.
This is not a caps0 runtime snapshot or complete physical/cache/ROM RAM total.

normal-task-snapshots.json separates twenty complete12-task snapshots before
the known normal reset and four after it (24 total;288 numeric stack rows).
Each task watermark is a lifetime minimum-free margin. Numeric IDs can reset or
refer to other lifetimes across boot; they are not persistent task identities.
Without each reserved stack size, these margins are not used bytes. The1152B
enumeration scratch lives on the existing loop stack. Deleted tasks/boot/ISR
stacks and initialization/rekey/all-task simultaneous peaks remain unmeasured.
No terminal worker watermark was captured. Raw samples support finite refusal/
recovery observations, not sustained availability or complete hostile-load proof.

Physical power interruption, interrupted management transitions, current queued
revocation/receipt recovery and matched MCU GET timing remain open. The selected
RF-on RNG guard has an RF-lifecycle precondition; it is not entropy certification,
historical key-generation proof or production custody/rollback qualification.

Original host/Linux evidence note:
These two public evidence files preserve original result/log bytes as base64 with SHA256, a decoded text view, source/tree/lock/compiler/binary identities, raw timing samples, named configurations and measurement limits. No device, credentials, enrolled identities, NVS content or native binary is included. The Linux GitHub artifact ZIP digest is the API-reported value; extracted files were independently checked against their retained manifest. No assertion is made that the ZIP itself was retained or independently hashed. Windows process/CPU observations and Linux requested-heap/process views include different overlapping domains and must not be summed or compared as a library-only RAM requirement. The larger Service cloud fixture is separate from the fixed SmallDevice/Constrained comparison.
