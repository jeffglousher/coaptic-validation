# General source review

The first shared-storage source6e892a9 had no actionable finding in a general
read-only review. After lifetime refinements, fresh review of measured90e3ef9
found a P2 custom-profile auto-trait regression: App inherited temporary scratch
Send/Sync restrictions from the empty provider marker and resident enum variant.
No other actionable correctness/security finding was reported. This measured
source is rejected by both that review and four CPU preservation bounds.

Correction bf195624c9080631767fcd8f3bdfd322fb6557df separates ResidentRxScratch
from temporary scratch, updates implementations and admission, and uses a function
marker for the empty provider. Four scratch-admission tests include custom Rc
scratch App Send+Sync assertions and independent resident read/write refusal
before entropy; all pass. Corrected library926 and footprint13 tests also pass.
This is a correctness repair, not an accepted performance optimization. Its
runtime has not been measured, and the failed performance hypothesis will not
be resampled merely because that repair landed. No production source is merged.
