# `rustzap ad` validation lab (Samba AD DC)

A **deliberately relay-vulnerable** Active Directory domain controller for
exercising `rustzap ad` end-to-end against a real LDAP/DNS server. **Lab only —
never expose this.**

Weaknesses seeded on purpose:
- `ldap server require strong auth = no` → unsigned simple binds accepted
  (the `ad/ldap-signing` condition).
- A ghost SPN `MSSQLSvc/ghost-db.corp.local:1433` on `GHOSTSRV$`, whose host has
  no DNS record (the `ad/ghost-spn` condition).
- A mock **WinRM-port NTLM responder** (`ntlm_responder.py`, port 5985) that returns
  a real NTLMSSP type-2 CHALLENGE with weak flags (no signing, no extended session
  security) — the `ad/ntlmv1` / `ad/ntlm-signing` conditions. It validates the
  client NTLM wire path + report correlation, **not** genuine Windows NTLM.

## Run

```bash
cd tests/ad-lab
docker compose up -d --build          # provisioning takes ~30-60s the first time

export RZ_AD_PASS='Passw0rd!'
cargo run -- ad --domain corp.local --dc-ip 127.0.0.1 \
  -u administrator --password-env RZ_AD_PASS \
  --target 127.0.0.1 --audit --checks all -o /tmp/ad-lab.json --yes

docker compose down -v                 # tear down
```

Expect `ad/ldap-signing`, `ad/ghost-spn`, `ad/computer`, `ad/ntlmv1`, and
`ad/ntlm-signing` findings, plus an **"NTLM relay exposure on <host>"** correlation
in `/tmp/ad-lab.json` (the DC host carries multiple relay-enablers).

> **Note on realism:** the responder is a stand-in for WinRM, so it validates the
> client NTLM handshake + verdict + correlation, not Windows-specific NTLM/LDAP
> behaviour. A genuine Windows DC (cloud VM or x86 hardware — GOAD does not run on
> Apple Silicon) is still needed to validate against real Windows semantics.
