# Layer 0 — the mandatory network boundary (network-policy companion)

> Source of truth: `docs/spec/SPEC.md` (v0.8) §3 (layer 0), §4 ("Network/roles — do
> FIRST"), §5. `docs/spec/decisions.md`: *"Mandatory network boundary — agent role
> reaches Postgres ONLY via the proxy host (pg_hba + network) … direct-to-DB bypass
> otherwise defeats all enforcement + audit. This is now a BLOCKING prerequisite,
> tested."* Issue #5.

`pg_hba.conf` is the **in-database** half of the boundary. A complete deployment pairs it
with a **network-layer** control so the two fail closed independently (defense in depth):
neither alone is the whole boundary.

## 1. In-database half — `pg_hba.conf` (this directory)

The agent role is permitted to connect **only from the proxy host's IP/CIDR**; every
other origin is `reject`ed at `pg_hba` (before authentication, before any query). Render
the rules with [`render-hba.sh`](render-hba.sh) from
[`pg_hba.agent-boundary.conf.template`](pg_hba.agent-boundary.conf.template) and place
them **above** any broad catch-all (`pg_hba.conf` is first-match, top-to-bottom):

```sh
deploy/hba/render-hba.sh --agent-role pgb_agent --proxy-cidr 10.0.0.5/32 \
  >> "$PGDATA/pg_hba.conf"
# then: pg_ctl reload   (or SELECT pg_reload_conf();)
```

Why this matters: without it, a compromised/jailbroken agent (or anyone holding the
agent's credentials) connects **direct-to-DB**, bypassing the proxy's read-only routing,
EXPLAIN-cost gate, byte/row cutoff, cumulative budget, and the hash-chained audit. The
proxy becomes meaningless. The Layer 1 WALL (hardened role) still bounds what such a
direct client can *do*, but the audit hole and the loss of cost/volume enforcement are
the reason this boundary is **blocking**.

## 2. Network-layer half (deployment companion — set this too)

`pg_hba` keys on the **source IP** Postgres observes. Harden the network so that IP can
only ever be the proxy's:

- **Security group / firewall:** allow inbound `5432/tcp` to the database **only from the
  proxy host's security group or IP**. Deny `5432` from app subnets, bastions, and the
  internet. The agent's app servers reach the **proxy**, never the DB.
- **Kubernetes `NetworkPolicy` (if applicable):** an ingress policy on the DB pod allowing
  `5432` only from the proxy pod's label selector; default-deny otherwise.
- **No NAT collisions:** ensure the proxy is not behind a shared NAT that makes other
  hosts appear to originate from `@PROXY_CIDR@`. Prefer a `/32` (single host) over a
  broad CIDR. If the proxy fleet scales, list each proxy `/32` (or its dedicated subnet).
- **TLS / SCRAM:** the agent authenticates with `scram-sha-256` (default `@AUTH@`);
  require TLS (`hostssl`) in production so credentials and traffic are encrypted on the
  wire between proxy and DB.

## 3. Local boundary simulation (how the test proves it)

`deploy/test/wall_matrix.sh` cannot add a second loopback alias without root, so it models
"proxy host vs. elsewhere" with two **real, already-present** loopback addresses:

| Address      | Models            | Agent-role rule | Expected on agent connect |
|--------------|-------------------|-----------------|---------------------------|
| `::1/128`    | **the proxy host**| `… scram-sha-256` | **ALLOWED**             |
| `127.0.0.1/32`| a non-proxy origin| `… reject`      | **REJECTED** at `pg_hba` |

The harness renders the template with `--proxy-cidr ::1/128`, then:

- connects as the agent **from `::1`** → succeeds (proves the proxy host can reach the DB);
- connects as the agent **from `127.0.0.1`** → fails with
  `FATAL: pg_hba.conf rejects connection for host "127.0.0.1", user "<agent>"` (proves a
  direct-to-DB connection from a non-proxy origin is refused — the §5 negative test).

`::1` is a stand-in. In production, `@PROXY_CIDR@` is the proxy's real IP/CIDR and **every
other origin is rejected** — exactly the boundary the table above demonstrates locally.
