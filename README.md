# Privacyflow v0.1.0

Safety-first VPN profile validation and rotation planning. This is a **dry-run starter**, not a system VPN controller.

## Run

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m privacyflow.cli validate config.example.toml
python -m privacyflow.cli rotation-plan config.example.toml
```

For editable install: `python -m pip install -e .` then use `privacyflow validate config.example.toml`.

## Bring your own provider profile

1. Copy the WireGuard `.conf` file from a provider or your own authorized server to `profiles/`.
2. Set file permissions to the current user only (Linux/macOS example: `chmod 600 profiles/my-provider.conf`).
3. Add the relative path to `config.example.toml`.
4. Never commit real `.conf` files or private keys.

## What this version does

- Validates base64 32-byte key shapes, endpoint port, interface addresses, AllowedIPs CIDRs and optional DNS addresses without printing key values. The bundled key material is demo-only and cannot connect to a VPN.
- Requires the kill-switch policy to remain enabled.
- Validates a minimum rotation interval and prints a dry-run order.

## What it does NOT do yet

It does not change MAC addresses, device IDs, interfaces, routes, firewall rules, DNS settings, or VPN connections. A later privileged Linux daemon must implement transactional connection switching, fail-closed routing, leak checks and emergency recovery before it is safe to automate real rotations.

MAC randomization is a local Wi-Fi/Ethernet privacy feature and is not equivalent to changing the public egress IP seen by websites. VPNs do not remove cookies, account identity, browser fingerprinting or provider/server logs. No 100% untraceability guarantee is possible.

---

## Part of the Gravion Toolkit

This repository holds one project from the four-project Gravion Toolkit. The projects are independent and can be used separately.

| Project | Purpose | Repository |
|---|---|---|
| localshare | Share a local development server through Cloudflare Quick or Named Tunnels | https://github.com/gravion-ux/localshare/tree/main |
| **This repository** | Validate authorised VPN profiles and plan safe rotation workflows | https://github.com/gravion-ux/privacyflow/tree/main |
| agent-browser | Run permission-aware browser tasks on allow-listed domains | https://github.com/gravion-ux/agent-browser/tree/main |
| gravion-trainner | Evaluate AI models against a JSONL dataset and report quality | https://github.com/gravion-ux/gravion-trainner/tree/main |

The four projects are **development foundations and MVP scaffolds**, not production services. They do not provide anonymity guarantees, CAPTCHA or anti-bot bypass, universal model retraining, or a managed multi-tenant sharing relay. See [the shared security notes](docs/SECURITY.md), [the threat model](docs/THREAT-MODEL.md) and [the roadmap](docs/ROADMAP.md) for the boundaries and the planned work.
