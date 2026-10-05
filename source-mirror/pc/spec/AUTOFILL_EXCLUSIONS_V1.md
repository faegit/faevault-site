# Autofill exclusions, version 1

The encrypted payload and PMVE metadata use the same `autofill_exclusions` object.
It contains active `packages` (Android), `hosts` (shared websites), and `processes`
(desktop application names), plus `states` keyed by `<category>:<normalized value>`.
Each state is `{ "updated_at": <UTC milliseconds>, "deleted": <boolean> }`.

Legacy list members without a state are active at timestamp zero. A state takes
precedence over a list member. Merge each key independently, choosing the greater
timestamp; deletion wins an equal timestamp. Retain deletion states and all three
categories, then derive sorted active lists from the merged states. A later
explicit addition can restore a deleted member. Edits use a timestamp greater
than the previously stored state to remain monotonic when the local clock moves
backward.

Local application preferences are a cache for locked/background autofill checks.
Edits must also commit to the current encrypted vault. The first upgrade must
migrate pre-existing local exclusions rather than overwrite them with empty vault
metadata. Following unlock, import, or synchronization, refresh the cache from
the committed vault result. Native categories remain distinct across platforms.

`autofill_exclusions_v1_fixtures.json` is the shared merge contract. Both clients
must verify the expected lists and commutativity for every case.
