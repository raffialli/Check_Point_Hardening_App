# Scan structure

`lib/collection.js` owns pagination and collection coverage. Object inventory and
access-rulebase reads use the same paginator. Successful earlier pages survive a
later failure, object dictionaries merge across pages, and repeated/non-advancing
pages stop with incomplete coverage. Cache keys include API endpoint, session,
domain, command, and request body. Normal scans use a bounded queue (default 10;
set `API_CONCURRENCY` to tune it). Large-environment mode retains its own limit.

`public/finding-model.js` is shared by the server, browser, and PDF generator.
It centralizes owner classification, gateway-name normalization, and target
extraction. Scan findings add `ownership` (scope, domain, target UID/type when
resolved), `evaluationStatus`, and `collection`. Existing `status` and evidence
tables remain compatible. Older reports without these fields use the table
adapter. `not-reported` means a legacy collector has not supplied coverage; it
must not be treated as proof of complete collection.

Collection describes the quality of evidence, not whether a setting is secure.
Partial/failed collection is displayed separately in the UI and both PDF layouts.
Incomplete stealth-rule searches do not assert that an unmatched gateway has no
stealth rule. This is an incremental extraction, not a rewrite of every evaluator.

`lib/operations.js` guards scan, refresh, logout, and remediation operations per
session. An overlap returns HTTP 409. Cancellation prevents queued/new API calls
from starting, lets in-flight calls finish, and keeps the prior completed report.
The operation guard remains held until tracked API work drains. Cancellation
does not undo changes and is exposed only for scans.

Run `npm run check` and `npm test` after changes. Tests use synthetic data only;
customer reports/debug logs must not be added as fixtures. Live API behavior still
requires lab verification across SMS, MDS, and Smart-1 Cloud.
