# certcheck 🔒

**SSL/TLS certificate inspector.** Zero dependencies, pure Python stdlib.

Inspect certificate validity, expiration, issuer details, and full certificate chains from any TLS endpoint. Built for automation — structured JSON output and meaningful exit codes.

> Part of the **Trust & Reliability Layer for Agentic AI** — provenance, economics, truth, and interop tools for people building on agentic models.

## Why it exists

SSL/TLS certificates are the backbone of trust on the internet, but checking them programmatically often requires OpenSSL or heavyweight libraries. certcheck gives you a single-file Python tool that inspects certs from any host:port — expiration, chain validation, SANs, and issuer details — with zero dependencies.

## One tool, many domains

| Domain | What certcheck does |
|---|---|
| 🔒 **Security** | Check cert expiry before it breaks production |
| 🤖 **Agentic AI** | Validate TLS endpoints in agent tool chains |
| 🛠️ **DevOps** | CI/CD cert monitoring and pre-deploy checks |
| 🔍 **Debugging** | Inspect cert chains and SAN mismatches |

## Install
```bash
git clone git@github.com:realMNohgee/certcheck.git
cd certcheck
python3 certcheck.py --help
```

## Quick start
```bash
# Check a certificate
python3 certcheck.py check example.com

# Show the full certificate chain
python3 certcheck.py chain example.com

# JSON output for automation
python3 certcheck.py check example.com --format json
```

Example output:
```
Host:         example.com:443
Subject:      CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers, L=Los Angeles, ST=California, C=US
Issuer:       CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US
Valid from:   2025-01-30 00:00:00 UTC
Valid until:  2026-03-02 23:59:59 UTC
Status:       ✓ VALID (228 days remaining)
SANs:         www.example.org, example.com, example.edu, example.net, example.org
```

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)** — the open, agent-agnostic marketplace for AI agent tools.
