# SentinelX Security Target

Disposable Docker target used for defensive monitoring integration tests.

The container runs OpenSSH and writes authentication events to the container
logging stream. It is intentionally isolated from production systems and is
used only as a reproducible security-monitoring target.
