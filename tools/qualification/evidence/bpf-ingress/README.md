# BPF ingress pilot receipt

[The unchanged review receipt](run-39254465762-review.json) records hosted run 39254465762, core 244809ebcd852cfeaf912bd2f5ba5956b6495bfc and companion 7d34275be771ee1b689c9005c2eb2745b74586e7. Its SHA256 is `a2b5b1a104567c9513420bb66f3c6e1f0dc90e24cba58549be915fa355368244`.

Each cycle has 4,556 executed BPF inputs (`kernel_cases_per_cycle`) **plus** 1,456 additional kernel-rejected short frames (`kernel_short_frame_refusals_per_cycle`), for 6,012 total vectors. These are additive counts, not a subset. Three cycles comprise two instrumented loads and one ordinary load.

The receipt includes actual kernel/verifier, counters, concurrent CPUs, ownership/cleanup, capability-refusal and live-byte controls. It is an observation-only SKB/XDP_PASS pilot on the named hosted kernel. It does not establish native NIC XDP support, application authentication, performance benefit or deployment across kernels. BPF vectors are separate from CoAP interoperability direction counts.
