#!/usr/bin/env python3
"""certcheck — SSL/TLS certificate inspector. Zero dependencies, pure Python stdlib."""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
from datetime import datetime, timezone


# ── Minimal ASN.1 DER parser for X.509 certs ──────────────────────────────

class ASN1Reader:
    """Minimal ASN.1 DER reader that navigates X.509 certificate structures."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def _read_byte(self) -> int:
        b = self._data[self._pos]
        self._pos += 1
        return b

    def _read_bytes(self, n: int) -> bytes:
        b = self._data[self._pos : self._pos + n]
        self._pos += n
        return b

    def _read_length(self) -> int:
        b = self._read_byte()
        if b & 0x80:
            num_octets = b & 0x7F
            length = 0
            for _ in range(num_octets):
                length = (length << 8) | self._read_byte()
            return length
        return b

    def _read_tlv(self):
        """Read a tag-length-value node. Returns (tag, length, value_or_reader)."""
        tag = self._read_byte()
        length = self._read_length()
        start = self._pos
        if tag & 0x20:  # constructed
            child = ASN1Reader(self._data[start : start + length])
            self._pos = start + length
            return tag, length, child
        else:
            value = self._data[start : start + length]
            self._pos = start + length
            return tag, length, value

    def read_node(self):
        """Read the next TLV node. Returns (tag, length, value_or_reader) or None."""
        if self._pos >= len(self._data):
            return None
        return self._read_tlv()

    def __len__(self) -> int:
        return len(self._data)


def _rdn_to_string(rdn_set: ASN1Reader) -> str:
    """Parse a SET of AttributeTypeAndValue into a string like 'CN=example.com'.

    Handles both SET (tag 0x31) and SEQUENCE (tag 0x30) containers.
    """
    parts = []
    while True:
        node = rdn_set.read_node()
        if node is None:
            break
        tag, length, container = node

        # Container may be a SET (tag 0x31) or SEQUENCE (tag 0x30)
        if tag == 0x31 and isinstance(container, ASN1Reader):
            # SET of SEQUENCEs — read each SEQUENCE inside
            while True:
                inner = container.read_node()
                if inner is None:
                    break
                inner_tag, _, atv = inner
                if inner_tag == 0x30 and isinstance(atv, ASN1Reader):
                    name_part = _parse_atv(atv)
                    if name_part:
                        parts.append(name_part)
        elif tag == 0x30 and isinstance(container, ASN1Reader):
            name_part = _parse_atv(container)
            if name_part:
                parts.append(name_part)

    return ", ".join(parts)


def _parse_atv(atv: ASN1Reader) -> str:
    """Parse a single AttributeTypeAndValue SEQUENCE (OID + value)."""
    oid_node = atv.read_node()
    val_node = atv.read_node()
    if oid_node is None or val_node is None:
        return ""
    _, _, oid_val = oid_node
    _, _, val_val = val_node
    if not isinstance(val_val, bytes) or not isinstance(oid_val, bytes):
        return ""
    # Map common OIDs to short names
    name_map = {
        b"\x55\x04\x03": "CN",
        b"\x55\x04\x06": "C",
        b"\x55\x04\x07": "L",
        b"\x55\x04\x08": "ST",
        b"\x55\x04\x0a": "O",
        b"\x55\x04\x0b": "OU",
    }
    short = name_map.get(oid_val, "?")
    val_tag = val_node[0]
    try:
        if val_tag == 0x0C:
            str_val = val_val.decode("utf-8", errors="replace")
        elif val_tag in (0x13, 0x16):
            str_val = val_val.decode("ascii", errors="replace")
        else:
            str_val = val_val.decode("latin-1", errors="replace")
    except Exception:
        str_val = val_val.hex()
    return f"{short}={str_val}"


def _parse_time(data: bytes):
    """Parse UTCTime or GeneralizedTime from DER bytes. Returns timezone-aware datetime or None."""
    s = data.decode("ascii", errors="replace")
    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    for fmt in ("%y%m%d%H%M%S%z", "%Y%m%d%H%M%S%z"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def parse_cert_from_pem(pem_data: str) -> dict:
    """Parse a single PEM-encoded X.509 certificate into a dict."""
    lines = [l.strip() for l in pem_data.splitlines()
             if l.strip() and not l.startswith("-----")]
    b64 = "".join(lines)
    try:
        der = base64.b64decode(b64)
    except Exception:
        return _empty_cert()

    result = _empty_cert()
    reader = ASN1Reader(der)

    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    node = reader.read_node()
    if node is None:
        return result
    tag, _, cert_seq = node
    if tag != 0x30 or not isinstance(cert_seq, ASN1Reader):
        return result

    tbs_node = cert_seq.read_node()
    if tbs_node is None:
        return result
    tbs_tag, _, tbs = tbs_node
    if tbs_tag != 0x30 or not isinstance(tbs, ASN1Reader):
        return result

    # TBSCertificate: version? serial signature issuer validity subject pubkey extensions?
    first_node = tbs.read_node()
    if first_node is None:
        return result
    first_tag, _, first_val = first_node

    # If [0] EXPLICIT (version), skip it; otherwise we just read serial
    if first_tag == 0xA0:
        # version wrapper consumed; next is serial
        pass
    else:
        # We already consumed serial. We'll proceed by re-reading from raw
        # Let's use a simpler scanning approach
        return _scan_tbs(ASN1Reader(tbs._data))

    # Now at: serial (INTEGER), signatureAlgorithm (SEQUENCE), issuer, validity, subject
    tbs.read_node()  # serial
    tbs.read_node()  # signatureAlgorithm

    # issuer
    issuer_node = tbs.read_node()
    if issuer_node and isinstance(issuer_node[2], ASN1Reader):
        result["issuer"] = _rdn_to_string(issuer_node[2])

    # validity
    validity_node = tbs.read_node()
    if validity_node and isinstance(validity_node[2], ASN1Reader):
        vreader = validity_node[2]
        nb = vreader.read_node()
        na = vreader.read_node()
        if nb and isinstance(nb[2], bytes):
            result["not_before"] = _parse_time(nb[2])
        if na and isinstance(na[2], bytes):
            result["not_after"] = _parse_time(na[2])

    # subject
    subject_node = tbs.read_node()
    if subject_node and isinstance(subject_node[2], ASN1Reader):
        result["subject"] = _rdn_to_string(subject_node[2])

    # Skip subjectPublicKeyInfo, then check for extensions [3]
    tbs.read_node()  # subjectPublicKeyInfo

    ext_node = tbs.read_node()
    if ext_node and ext_node[0] == 0xA3 and isinstance(ext_node[2], ASN1Reader):
        ext_reader = ext_node[2]
        while True:
            ext = ext_reader.read_node()
            if ext is None:
                break
            ext_tag, _, ext_val = ext
            if ext_tag != 0x30 or not isinstance(ext_val, ASN1Reader):
                continue
            oid_node = ext_val.read_node()
            crit_node = ext_val.read_node()
            val_node = ext_val.read_node()
            if oid_node is None or val_node is None:
                continue
            oid_bytes = oid_node[2] if isinstance(oid_node[2], bytes) else b""
            # SAN OID: 2.5.29.17 = 55 1D 11
            if oid_bytes == b"\x55\x1d\x11":
                san_bytes = val_node[2] if isinstance(val_node[2], bytes) else b""
                if san_bytes:
                    try:
                        san_reader = ASN1Reader(san_bytes)
                        result["sans"] = _parse_sans(san_reader)
                    except Exception:
                        pass
            # Skip critical field if present (BOOLEAN)
            # already handled by reading crit_node and val_node

    return result


def _scan_tbs(reader: ASN1Reader) -> dict:
    """Scan TBS structure for issuer, validity, subject by position."""
    result = _empty_cert()
    # Skip: serial (INTEGER), sigalg (SEQUENCE)
    reader.read_node()  # serial
    reader.read_node()  # sigAlg

    # issuer
    node = reader.read_node()
    if node and isinstance(node[2], ASN1Reader):
        result["issuer"] = _rdn_to_string(node[2])

    # validity
    node = reader.read_node()
    if node and isinstance(node[2], ASN1Reader):
        vreader = node[2]
        nb = vreader.read_node()
        na = vreader.read_node()
        if nb and isinstance(nb[2], bytes):
            result["not_before"] = _parse_time(nb[2])
        if na and isinstance(na[2], bytes):
            result["not_after"] = _parse_time(na[2])

    # subject
    node = reader.read_node()
    if node and isinstance(node[2], ASN1Reader):
        result["subject"] = _rdn_to_string(node[2])

    # Skip subjectPublicKeyInfo, check extensions [3]
    reader.read_node()  # SPKI

    node = reader.read_node()
    if node and node[0] == 0xA3 and isinstance(node[2], ASN1Reader):
        ext_reader = node[2]
        while True:
            ext = ext_reader.read_node()
            if ext is None:
                break
            ext_tag, _, ext_val = ext
            if ext_tag != 0x30 or not isinstance(ext_val, ASN1Reader):
                continue
            oid_node = ext_val.read_node()
            crit_node = ext_val.read_node()
            val_node = ext_val.read_node()
            if oid_node is None or val_node is None:
                continue
            oid_bytes = oid_node[2] if isinstance(oid_node[2], bytes) else b""
            if oid_bytes == b"\x55\x1d\x11":
                san_bytes = val_node[2] if isinstance(val_node[2], bytes) else b""
                if san_bytes:
                    try:
                        san_reader = ASN1Reader(san_bytes)
                        result["sans"] = _parse_sans(san_reader)
                    except Exception:
                        pass

    return result


def _empty_cert() -> dict:
    return {"subject": "", "issuer": "", "not_before": None, "not_after": None, "sans": []}


def _parse_sans(reader: ASN1Reader):
    """Parse SubjectAltName extension value (SEQUENCE OF GeneralName)."""
    sans = []
    while True:
        node = reader.read_node()
        if node is None:
            break
        tag, _, val = node
        if isinstance(val, bytes):
            if tag == 2:  # dNSName
                try:
                    sans.append(val.decode("ascii", errors="replace"))
                except Exception:
                    pass
            elif tag == 7:  # iPAddress
                try:
                    if len(val) == 4:
                        sans.append(socket.inet_ntop(socket.AF_INET, val))
                    elif len(val) == 16:
                        sans.append(socket.inet_ntop(socket.AF_INET6, val))
                except Exception:
                    pass
    return sans


# ── SSL utilities ─────────────────────────────────────────────────────────

def get_cert_from_socket(host: str, port: int, timeout: float) -> dict:
    """Connect via SSL and return the peer certificate dict.

    Uses default verification context for full cert dict. Falls back to
    get_server_certificate + PEM parsing for self-signed certs.
    """
    # Primary: use default context (gives full cert dict with SANs)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert and cert.get("subject"):
                    return cert
    except ssl.SSLCertVerificationError:
        # Self-signed or untrusted — fall through to PEM approach
        pass
    except ssl.SSLError:
        pass

    # Fallback: get PEM and parse the first cert
    try:
        return _get_cert_via_pem(host, port, timeout)
    except Exception:
        return {}


def _get_cert_via_pem(host: str, port: int, timeout: float) -> dict:
    """Get cert by fetching PEM and parsing with ASN.1 parser."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                return {}
            # Parse DER directly
            reader = ASN1Reader(der)
            node = reader.read_node()
            if node is None:
                return {}
            tag, _, cert_seq = node
            if tag != 0x30 or not isinstance(cert_seq, ASN1Reader):
                return {}

            tbs_node = cert_seq.read_node()
            if tbs_node is None:
                return {}
            tbs_tag, _, tbs = tbs_node
            if tbs_tag != 0x30 or not isinstance(tbs, ASN1Reader):
                return {}

            return _scan_tbs(tbs)


def get_cert_chain_pem(host: str, port: int, timeout: float) -> str:
    """Get the full PEM certificate chain from the server."""
    try:
        return ssl.get_server_certificate((host, port))
    except TypeError:
        # Python 3.9: no timeout kwarg; use default timeout
        return ssl.get_server_certificate((host, port))


def split_pem_chain(pem_data: str):
    """Split a PEM string containing multiple certificates into individual PEM certs."""
    certs = []
    for block in pem_data.split("-----BEGIN CERTIFICATE-----"):
        block = block.strip()
        if not block:
            continue
        certs.append("-----BEGIN CERTIFICATE-----\n" + block)
    return certs


def format_dt(dt) -> str:
    """Format datetime to readable string."""
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def days_remaining(not_after) -> int:
    """Calculate days until cert expiry."""
    if not_after is None:
        return -1
    now = datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    delta = not_after - now
    return delta.days


# ── X.509 name formatting ─────────────────────────────────────────────────

def _format_x509_name(name):
    """Format x509 name tuple list to string."""
    if not name:
        return ""
    parts = []
    for component in name:
        if isinstance(component, tuple):
            for key, value in component:
                parts.append(f"{key}={value}")
        elif isinstance(component, list):
            for item in component:
                if isinstance(item, tuple) and len(item) == 2:
                    parts.append(f"{item[0]}={item[1]}")
    return ", ".join(parts)


def _extract_sans_from_dict(cert: dict):
    """Extract SANs from getpeercert() dict format."""
    sans = []
    san_data = cert.get("subjectAltName", [])
    for entry in san_data:
        if isinstance(entry, tuple) and len(entry) == 2:
            sans.append(entry[1])
    return sans


def _parse_ssl_date(date_str: str):
    """Parse an SSL date string like 'Jan 1 00:00:00 2025 GMT'."""
    if not date_str:
        return None
    for tz_suffix in (" GMT", " UTC"):
        if date_str.endswith(tz_suffix):
            date_str = date_str[:-len(tz_suffix)]
            break
    for fmt in ("%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _hostname_matches_sans(hostname: str, sans):
    """Check if hostname matches any SAN including wildcards."""
    for san in sans:
        if san == hostname:
            return True
        if san.startswith("*."):
            suffix = san[2:]
            if hostname.endswith("." + suffix) or hostname == suffix:
                return True
    return False


# ── Subcommand handlers ───────────────────────────────────────────────────

def cmd_check(args) -> int:
    """Check a single SSL/TLS certificate."""
    host = args.host
    port = args.port
    timeout = args.timeout

    # Connect and get cert
    try:
        cert = get_cert_from_socket(host, port, timeout)
    except socket.timeout:
        print(f"Error: connection to {host}:{port} timed out", file=sys.stderr)
        return 2
    except ConnectionRefusedError:
        print(f"Error: connection refused to {host}:{port}", file=sys.stderr)
        return 2
    except socket.gaierror as e:
        print(f"Error: cannot resolve hostname '{host}': {e}", file=sys.stderr)
        return 2
    except ssl.SSLError as e:
        print(f"Error: SSL error for {host}:{port}: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"Error: cannot connect to {host}:{port}: {e}", file=sys.stderr)
        return 2

    if not cert:
        print(f"Error: no certificate returned from {host}:{port}", file=sys.stderr)
        return 2

    # Extract fields (support both dict formats: from getpeercert and from PEM parsing)
    if "subject" in cert and isinstance(cert["subject"], str):
        # PEM-parsed cert
        subject = cert["subject"]
        issuer = cert["issuer"]
        not_before = cert.get("not_before")
        not_after = cert.get("not_after")
        sans = cert.get("sans", [])
    else:
        # getpeercert dict
        subject = _format_x509_name(cert.get("subject", []))
        issuer = _format_x509_name(cert.get("issuer", []))
        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")
        not_before = _parse_ssl_date(not_before_str) if not_before_str else None
        not_after = _parse_ssl_date(not_after_str) if not_after_str else None
        sans = _extract_sans_from_dict(cert)

    days = days_remaining(not_after)
    expired = not_after is not None and days < 0

    # Warnings
    warnings = []
    if subject and issuer and subject == issuer:
        warnings.append("Self-signed certificate")
    if sans and host not in sans and not _hostname_matches_sans(host, sans):
        warnings.append(f"Hostname '{host}' does not match any SAN")

    if args.format == "json":
        output = {
            "host": host,
            "port": port,
            "subject": subject,
            "issuer": issuer,
            "not_before": format_dt(not_before),
            "not_after": format_dt(not_after),
            "days_remaining": days,
            "is_expired": expired,
            "sans": sans,
            "warnings": warnings,
            "valid": not expired,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Host:         {host}:{port}")
        print(f"Subject:      {subject}")
        print(f"Issuer:       {issuer}")
        print(f"Valid from:   {format_dt(not_before)}")
        print(f"Valid until:  {format_dt(not_after)}")
        if expired:
            status = "\u26a0 EXPIRED"
        elif days > 30:
            status = "\u2713 VALID"
        else:
            status = f"\u26a0 EXPIRES IN {days} DAYS"
        print(f"Status:       {status} ({days} days remaining)")
        if sans:
            shown = sans[:8]
            print(f"SANs:         {', '.join(shown)}")
            if len(sans) > 8:
                print(f"              ... and {len(sans) - 8} more")
        if warnings:
            for w in warnings:
                print(f"\u26a0 {w}")

    return 1 if expired else 0


def cmd_chain(args) -> int:
    """Show full certificate chain."""
    host = args.host
    port = args.port
    timeout = getattr(args, "timeout", 10)

    try:
        pem_data = get_cert_chain_pem(host, port, timeout)
    except socket.timeout:
        print(f"Error: connection to {host}:{port} timed out", file=sys.stderr)
        return 2
    except ConnectionRefusedError:
        print(f"Error: connection refused to {host}:{port}", file=sys.stderr)
        return 2
    except socket.gaierror as e:
        print(f"Error: cannot resolve hostname '{host}': {e}", file=sys.stderr)
        return 2
    except ssl.SSLError as e:
        print(f"Error: SSL error for {host}:{port}: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"Error: cannot connect to {host}:{port}: {e}", file=sys.stderr)
        return 2

    certs_pem = split_pem_chain(pem_data)
    chain = []
    for pem in certs_pem:
        info = parse_cert_from_pem(pem)
        chain.append(info)

    if args.format == "json":
        output = {
            "host": host,
            "port": port,
            "chain": [
                {
                    "index": i,
                    "subject": c.get("subject", ""),
                    "issuer": c.get("issuer", ""),
                    "not_before": format_dt(c.get("not_before")),
                    "not_after": format_dt(c.get("not_after")),
                    "days_remaining": days_remaining(c.get("not_after")),
                    "is_expired": (
                        c.get("not_after") is not None
                        and days_remaining(c.get("not_after")) < 0
                    ),
                    "sans": c.get("sans", []),
                }
                for i, c in enumerate(chain)
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Certificate chain for {host}:{port} "
              f"({len(chain)} cert{'s' if len(chain) != 1 else ''})")
        print()
        for i, cert in enumerate(chain):
            if len(chain) == 1:
                label = "Server cert"
            elif i == 0:
                label = "Server cert"
            elif i == len(chain) - 1:
                label = "Root CA"
            else:
                label = f"Intermediate CA {i}"
            days = days_remaining(cert.get("not_after"))
            expired = cert.get("not_after") is not None and days < 0
            status = "EXPIRED" if expired else "valid"
            print(f"  [{i}] {label}")
            print(f"      Subject:      {cert.get('subject', '')}")
            print(f"      Issuer:       {cert.get('issuer', '')}")
            print(f"      Valid until:  {format_dt(cert.get('not_after'))}")
            print(f"      Status:       {status} ({days} days)")
            if cert.get("sans"):
                print(f"      SANs:         {', '.join(cert['sans'][:5])}")
            print()

    return 0


# ── CLI entry point ───────────────────────────────────────────────────────

def main() -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format")

    p = argparse.ArgumentParser(
        description="certcheck — SSL/TLS certificate inspector"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # check
    s_check = sub.add_parser("check", parents=[common],
                             help="Check certificate validity")
    s_check.add_argument("host", help="Hostname to check")
    s_check.add_argument("--port", type=int, default=443,
                         help="Port number (default: 443)")
    s_check.add_argument("--timeout", type=float, default=10.0,
                         help="Connection timeout in seconds (default: 10)")

    # chain
    s_chain = sub.add_parser("chain", parents=[common],
                             help="Show full certificate chain")
    s_chain.add_argument("host", help="Hostname to check")
    s_chain.add_argument("--port", type=int, default=443,
                         help="Port number (default: 443)")
    s_chain.add_argument("--timeout", type=float, default=10.0,
                         help="Connection timeout in seconds (default: 10)")

    args = p.parse_args()

    if args.cmd == "check":
        return cmd_check(args)
    elif args.cmd == "chain":
        return cmd_chain(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
