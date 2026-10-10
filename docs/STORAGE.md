# SQLite event storage and simulated mitigation

`SQLiteStore` creates three tables in the database path supplied by the caller:

- `traffic_windows` stores one aggregate feature record per aligned window, duration, and source kind.
- `detection_events` stores alert labels and reasons linked to a window. Normal results are not inserted as alerts.
- `mitigation_events` records a temporary block decision in `simulation` mode with a validated IP address and UTC expiry time.

Window and alert writes are idempotent. A window has a unique `(window_start, window_seconds, source_kind)` key. Alert events use a stable hash of the window identity, source, label, and reasons, so dashboard reruns do not repeatedly add an identical alert. A second alert for the same window can be stored when its label or reason differs.

## Simulated blocklist

`record_simulated_block` only writes a database row. It does not invoke Windows Firewall, iptables, or another enforcement mechanism. Inputs require a valid IPv4/IPv6 address, a non-empty reason, and a positive TTL. `active_simulated_blocks` returns only entries whose UTC expiry is still in the future; expired decisions remain available in `list_mitigation_events` for audit history.

The dashboard can record a manually selected IP as a simulated block, with an expiry. A detection alert does not automatically become a simulated block. Real enforcement is not implemented.

## Example

```python
from pathlib import Path
from sentinelshield.storage import SQLiteStore

store = SQLiteStore(Path("data/sentinelshield.sqlite3"))
store.record_window(features)
store.record_detection(features, detection_result)
store.record_simulated_block(
    "192.0.2.10",
    reason="manual controlled demonstration",
    ttl_seconds=300,
)
```

The database path should be a local runtime-data path; SQLite files are ignored by Git. The dashboard uses `data/sentinelshield.sqlite3` by default and accepts `SENTINELSHIELD_DATABASE` to select a different path. The store is synchronous and opens a connection per operation, which is suitable for the current small local project. It keeps no raw packets or uploaded capture files.
