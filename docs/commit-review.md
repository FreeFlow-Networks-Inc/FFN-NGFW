# Effective configuration review

The Commit dialog keeps the PAN-style Preview / Validate / Commit workflow.
Preview combines candidate XML with the existing SQL resource mirror **in
memory**, then constructs the proposed running configuration for the selected
scope. No configuration, history, lock, or hardware settings are written during
review. Before/after values and change counts describe that same proposal.

Validate checks policy compilation and commissioned policy providers, including
the NAT dataplane preflight when required. It is **not** a complete configd dry
run: other settings still undergo configd validation during apply. Unsupported
enabled policy engines block promotion. Successful validation never means that
traffic handling has changed.

The UI requires validation before enabling Commit. Its revision binds candidate
XML, running XML, SQL-derived settings and scope. Changes during review or commit
preparation invalidate the review. The server serializes Commit requests within
the manager process, validates before hardware invalidation, passes the effective
scope to the hardware barrier, and promotes the same document it validated.
Partial history counts include only promoted changes; other candidate edits remain
pending. Existing API clients may omit the revision; server validation still runs.
This is optimistic revision checking, not a cross-process configuration transaction.

API:

```
GET /api/config/review?validate=false
GET /api/config/review?validate=true&partial_xpath=device.setup.management
POST /api/config/commit
{"description":"Reviewed change","partial_xpath":null,"expected_revision":"<review revision>"}
```

FFN-CLI uses the same authenticated read-only review endpoint:

```
show policies commit-preview
request policies commit-validate
request policies commit-validate device.setup.management
```

Commit requires an administrative role. The result distinguishes saving running
configuration, local application, and publishing to agents. Publication does not
prove CP/DP convergence. Use Tasks and agent status to verify runtime results.
On an interrupted request, inspect running configuration before retrying.

Review redacts credential fields by path and escapes displayed configuration and
lock text. The dialog shows up to 500 change rows; the API/CLI returns the complete
diff. A custom partial scope must name an existing candidate subtree. Deleting an
entire subtree requires committing its parent or the full configuration. Legacy
SQL resources remain separately owned: reverting candidate XML does not discard
their SQL edits; the UI tells the operator to preview them again.

## Sysroot reference

Read-only inspection used `/mnt/clones/5220-sysroot1-full/var/appweb/htdocs` on the
reference VM. Its help references PAN-OS 9.0, so it does not establish pixel-level
conformance to the requested PAN-OS 12.1 frontend. Findings inform original FFN
implementation; vendor source and assets are not included.

| Reference | Observation | SHA-256 |
| --- | --- | --- |
| `js/pan/mainui/commit/FWCommitViewer.js` | Separate Commit and Validate actions, scope and description | `abc453f8c2befaf4e1dbd27862dae6270171cc5a2cc1a4c4a09535eb3a248374` |
| `js/pan/mainui/commit/CommitUtils.js` | Pending-change checks and partial/full scope | `4f64a106256d48af5b050931a782168ca3d653d8f280b06ff0f96240f8e8d62e` |
| `js/pan/mainui/CommitStatusViewer.js` | Pending, warning and completed states | `c5926ca8ca28c75eb270cd144545c943ede54b37b66527836a9f699b728f2a49` |
| `scripts/status-job-single.xsl` | Separate job status, result, progress and warnings | `5b1b683b4eadd1126cd30cd9af97749eee8705d91c977d595672bf31f7dacb70` |
| `PAN_help/en/commit-changes.html.gz` | Preview, Validate, Commit and scope filters | `362b3c0d795cf64ffaa1666dbc5a8fc3458a8858238e347880f000810bd5d654` |

The VM's `scripts/qos.js` also confirms separate aggregate/class bandwidth and
clear-text/tunnel interface controls. That reference does not supply an FFN QoS
enforcement provider; QoS, PBF and Decryption runtime activation remain blocked
until their providers are implemented and commissioned.
