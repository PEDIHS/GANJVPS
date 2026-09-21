#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

ETC_DIR = Path("/etc/ganj-vps")
STATE_DIR = Path("/var/lib/ganj-vps")
BACKUP_DIR = STATE_DIR / "backups"
PUBLISH_FILE = ETC_DIR / "web-publish.json"
HAPROXY_CFG = Path(os.environ.get("GANJ_HAPROXY_CONFIG", "/etc/haproxy/haproxy.cfg"))
HAPROXY_CERT_DIR = Path("/etc/haproxy/certs")
RENEW_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/ganj-web-haproxy")

WEB_APP_HOST = "127.0.0.1"
WEB_APP_PORT = 9877
WEB_TLS_HOST = "127.0.0.1"
WEB_TLS_PORT = 9878
ACME_HOST = "127.0.0.1"
ACME_PORT = 9880

HTTP_BEGIN = "# BEGIN GANJ WEB HTTP"
HTTP_END = "# END GANJ WEB HTTP"
SNI_BEGIN = "# BEGIN GANJ WEB SNI"
SNI_END = "# END GANJ WEB SNI"
TLS_BEGIN = "# BEGIN GANJ WEB TLS"
TLS_END = "# END GANJ WEB TLS"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.IGNORECASE,
)


def _run(
    argv: list[str],
    *,
    check: bool = True,
    timeout: int = 30,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout,
    )


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _domain(value: str) -> str:
    value = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise RuntimeError("invalid_web_domain")
    return value


def _safe_name(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", domain.lower()).strip("-.")


def _strip_block(text: str, begin: str, end: str) -> str:
    if begin not in text:
        return text
    if end not in text:
        raise RuntimeError(f"haproxy_marker_corrupt:{begin}")
    start = text.index(begin)
    finish = text.index(end, start) + len(end)
    left = text[:start].rstrip()
    right = text[finish:].lstrip("\n")
    if left and right:
        return left + "\n\n" + right
    return (left + right).lstrip("\n")


def _strip_web_blocks(text: str) -> str:
    for begin, end in (
        (HTTP_BEGIN, HTTP_END),
        (SNI_BEGIN, SNI_END),
        (TLS_BEGIN, TLS_END),
    ):
        text = _strip_block(text, begin, end)
    return text.rstrip() + "\n"


def _insert_sni_block(text: str, domain: str) -> str:
    lines = text.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == "frontend ft_single_443"),
        None,
    )
    if start is None:
        raise RuntimeError("haproxy_ft_single_443_not_found")

    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i] and not lines[i][0].isspace() and re.match(
            r"^(frontend|backend|listen|global|defaults)\b", lines[i]
        ):
            end = i
            break

    default_index = next(
        (
            i
            for i in range(start + 1, end)
            if lines[i].strip().startswith("default_backend ")
        ),
        None,
    )
    if default_index is None:
        raise RuntimeError("haproxy_443_default_backend_not_found")

    block = [
        f"    {SNI_BEGIN}",
        f"    acl sni_ganj_web req.ssl_sni -i {domain}",
        "    use_backend be_ganj_web_tls if sni_ganj_web",
        f"    {SNI_END}",
    ]
    lines[default_index:default_index] = block
    return "\n".join(lines).rstrip() + "\n"


def _http_block() -> str:
    return f"""
{HTTP_BEGIN}
frontend ft_ganj_web_http
    mode http
    bind 0.0.0.0:80
    bind [::]:80 v6only
    acl ganj_acme path_beg /.well-known/acme-challenge/
    http-request redirect scheme https code 301 unless ganj_acme
    use_backend be_ganj_web_acme if ganj_acme

backend be_ganj_web_acme
    mode http
    server certbot {ACME_HOST}:{ACME_PORT}
{HTTP_END}
""".strip()


def _tls_block(pem_path: Path) -> str:
    return f"""
{TLS_BEGIN}
backend be_ganj_web_tls
    mode tcp
    server ganj_web_tls {WEB_TLS_HOST}:{WEB_TLS_PORT} send-proxy-v2

frontend ft_ganj_web_tls
    mode http
    bind {WEB_TLS_HOST}:{WEB_TLS_PORT} accept-proxy ssl crt {pem_path} alpn h2,http/1.1
    option httplog
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    http-request set-header X-Forwarded-For %[src]
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    default_backend be_ganj_web_app

backend be_ganj_web_app
    mode http
    option httpchk GET /healthz
    http-check expect status 200
    server ganj_web {WEB_APP_HOST}:{WEB_APP_PORT} check
{TLS_END}
""".strip()


def _port80_conflict(base_text: str) -> bool:
    for raw in base_text.splitlines():
        line = raw.strip()
        if not line.startswith("bind "):
            continue
        if re.search(r"(?<!\d):80(?:\s|$)", line):
            return True
    return False


def _socket_owner(port: int) -> str:
    try:
        p = _run(["ss", "-H", "-lntp"], timeout=5)
    except Exception:
        return ""
    pattern = re.compile(rf":{int(port)}\b")
    return "\n".join(
        line for line in p.stdout.splitlines() if pattern.search(line)
    )


def _backup_haproxy() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"haproxy-web-{stamp}.cfg"
    shutil.copy2(HAPROXY_CFG, target)
    os.chmod(target, 0o600)
    return target


def _validate_haproxy(candidate: Path | None = None) -> None:
    path = candidate or HAPROXY_CFG
    p = _run(
        ["haproxy", "-c", "-f", str(path)],
        check=False,
        timeout=20,
    )
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()[-2000:]
        raise RuntimeError(f"haproxy_validation_failed:{detail}")


def _reload_haproxy() -> None:
    p = _run(
        ["systemctl", "reload", "haproxy.service"],
        check=False,
        timeout=20,
    )
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()[-1000:]
        raise RuntimeError(f"haproxy_reload_failed:{detail}")


def _apply_haproxy(text: str) -> None:
    current = HAPROXY_CFG.read_text(encoding="utf-8")
    if text == current:
        return
    backup = _backup_haproxy()
    candidate = HAPROXY_CFG.with_name(HAPROXY_CFG.name + ".ganj-web-candidate")
    candidate.write_text(text, encoding="utf-8")
    try:
        _validate_haproxy(candidate)
        HAPROXY_CFG.write_text(text, encoding="utf-8")
        try:
            _reload_haproxy()
        except Exception:
            shutil.copy2(backup, HAPROXY_CFG)
            _reload_haproxy()
            raise
    finally:
        candidate.unlink(missing_ok=True)


def _ensure_http_challenge_route() -> None:
    current = HAPROXY_CFG.read_text(encoding="utf-8")
    base = _strip_block(current, HTTP_BEGIN, HTTP_END).rstrip() + "\n"
    if _port80_conflict(base):
        owner = _socket_owner(80)
        raise RuntimeError(
            "port_80_already_managed:"
            + (owner[:400] if owner else "haproxy_config")
        )
    desired = base.rstrip() + "\n\n" + _http_block() + "\n"
    _apply_haproxy(desired)


def _cert_paths(domain: str) -> tuple[Path, Path]:
    root = Path("/etc/letsencrypt/live") / domain
    return root / "fullchain.pem", root / "privkey.pem"


def _build_pem(domain: str, cert_path: Path, key_path: Path) -> Path:
    if not cert_path.is_file():
        raise RuntimeError(f"certificate_not_found:{cert_path}")
    if not key_path.is_file():
        raise RuntimeError(f"private_key_not_found:{key_path}")

    HAPROXY_CERT_DIR.mkdir(parents=True, exist_ok=True)
    pem_path = HAPROXY_CERT_DIR / f"ganj-web-{_safe_name(domain)}.pem"
    content = cert_path.read_bytes().rstrip() + b"\n" + key_path.read_bytes().rstrip() + b"\n"
    tmp = pem_path.with_name(pem_path.name + ".tmp")
    tmp.write_bytes(content)
    os.chmod(tmp, 0o600)
    os.replace(tmp, pem_path)
    return pem_path


def _ensure_firewall() -> None:
    if not shutil.which("ufw"):
        return
    status = _run(["ufw", "status"], check=False, timeout=8)
    first = (status.stdout or "").splitlines()
    active = bool(first and first[0].strip().lower() == "status: active")
    if not active:
        return
    for port, comment in (
        ("80/tcp", "GANJ Web ACME"),
        ("443/tcp", "GANJ Web HTTPS"),
    ):
        _run(
            ["ufw", "allow", port, "comment", comment],
            check=False,
            timeout=15,
        )


def _install_renew_hook() -> None:
    RENEW_HOOK.parent.mkdir(parents=True, exist_ok=True)
    RENEW_HOOK.write_text(
        "#!/bin/sh\n"
        "exec /opt/ganj-vps/venv/bin/python "
        "/opt/ganj-vps/web_publish.py refresh >/dev/null 2>&1\n",
        encoding="utf-8",
    )
    os.chmod(RENEW_HOOK, 0o755)


def _issue_certbot(domain: str) -> tuple[Path, Path, str]:
    if not shutil.which("certbot"):
        raise RuntimeError("certbot_not_installed")

    _ensure_http_challenge_route()

    email = f"ganj-{secrets.token_hex(5)}@pedramhs.ir"
    argv = [
        "certbot",
        "certonly",
        "--standalone",
        "--preferred-challenges",
        "http",
        "--http-01-address",
        ACME_HOST,
        "--http-01-port",
        str(ACME_PORT),
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        "--keep-until-expiring",
        "-d",
        domain,
    ]
    p = _run(argv, check=False, timeout=180)
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()[-2500:]
        raise RuntimeError(f"certbot_failed:{detail}")

    cert_path, key_path = _cert_paths(domain)
    if not cert_path.exists() or not key_path.exists():
        raise RuntimeError("certbot_certificate_paths_missing")
    _install_renew_hook()
    return cert_path, key_path, email


def _full_haproxy_config(domain: str, pem_path: Path) -> str:
    current = HAPROXY_CFG.read_text(encoding="utf-8")
    base = _strip_web_blocks(current)
    if _port80_conflict(base):
        owner = _socket_owner(80)
        raise RuntimeError(
            "port_80_already_managed:"
            + (owner[:400] if owner else "haproxy_config")
        )
    base = _insert_sni_block(base, domain)
    return (
        base.rstrip()
        + "\n\n"
        + _http_block()
        + "\n\n"
        + _tls_block(pem_path)
        + "\n"
    )


def _check_local_web() -> None:
    try:
        with socket.create_connection((WEB_APP_HOST, WEB_APP_PORT), timeout=3):
            pass
    except OSError as exc:
        raise RuntimeError("ganj_web_service_not_reachable") from exc


def _verify_tls_route(domain: str) -> bool:
    if not shutil.which("openssl"):
        return True
    p = _run(
        [
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:443",
            "-servername",
            domain,
            "-brief",
        ],
        check=False,
        timeout=12,
        input_text="",
    )
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode == 0 and (
        "CONNECTION ESTABLISHED" in out or "Protocol version" in out
    )


def configure(
    domain: str,
    *,
    auto_cert: bool,
    cert_path: str | None = None,
    key_path: str | None = None,
) -> dict[str, Any]:
    domain = _domain(domain)
    if not HAPROXY_CFG.exists():
        raise RuntimeError("haproxy_config_not_found")
    _check_local_web()

    try:
        socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("web_domain_dns_not_resolved") from exc

    _ensure_firewall()
    original_haproxy = HAPROXY_CFG.read_text(encoding="utf-8")
    try:
        if auto_cert:
            cert, key, email = _issue_certbot(domain)
            cert_method = "certbot"
        else:
            if cert_path and key_path:
                cert, key = Path(cert_path), Path(key_path)
            else:
                cert, key = _cert_paths(domain)
            email = None
            cert_method = "existing"

        pem = _build_pem(domain, cert, key)
        desired = _full_haproxy_config(domain, pem)
        _apply_haproxy(desired)
    except Exception:
        try:
            current = HAPROXY_CFG.read_text(encoding="utf-8")
            if current != original_haproxy:
                _apply_haproxy(original_haproxy)
        except Exception:
            pass
        raise

    payload = {
        "domain": domain,
        "url": f"https://{domain}/",
        "certificate_method": cert_method,
        "certificate_path": str(cert),
        "private_key_path": str(key),
        "haproxy_pem": str(pem),
        "web_app": f"{WEB_APP_HOST}:{WEB_APP_PORT}",
        "web_tls": f"{WEB_TLS_HOST}:{WEB_TLS_PORT}",
        "acme_listener": f"{ACME_HOST}:{ACME_PORT}",
        "configured_at": int(time.time()),
        "certbot_email": email,
    }
    _save(PUBLISH_FILE, payload, 0o600)

    verified = _verify_tls_route(domain)
    payload["local_tls_verified"] = bool(verified)
    _save(PUBLISH_FILE, payload, 0o600)
    return payload


def refresh() -> dict[str, Any]:
    cfg = _load(PUBLISH_FILE, {})
    if not cfg:
        raise RuntimeError("web_publish_not_configured")
    domain = _domain(str(cfg.get("domain") or ""))
    cert = Path(str(cfg.get("certificate_path") or ""))
    key = Path(str(cfg.get("private_key_path") or ""))
    pem = _build_pem(domain, cert, key)

    desired = _full_haproxy_config(domain, pem)
    _apply_haproxy(desired)
    cfg["haproxy_pem"] = str(pem)
    cfg["certificate_refreshed_at"] = int(time.time())
    cfg["local_tls_verified"] = bool(_verify_tls_route(domain))
    _save(PUBLISH_FILE, cfg, 0o600)
    return cfg


def remove() -> dict[str, Any]:
    current = HAPROXY_CFG.read_text(encoding="utf-8")
    desired = _strip_web_blocks(current)
    _apply_haproxy(desired)
    cfg = _load(PUBLISH_FILE, {})
    PUBLISH_FILE.unlink(missing_ok=True)
    return {
        "ok": True,
        "domain": cfg.get("domain"),
        "certificate_preserved": True,
    }


def status() -> dict[str, Any]:
    cfg = _load(PUBLISH_FILE, {})
    service = _run(
        ["systemctl", "is-active", "ganj-vps-web.service"],
        check=False,
        timeout=5,
    ).stdout.strip()
    result = {
        "configured": bool(cfg),
        "service": service or "unknown",
        "bind": f"{WEB_APP_HOST}:{WEB_APP_PORT}",
        "public_url": cfg.get("url"),
        "domain": cfg.get("domain"),
        "certificate_method": cfg.get("certificate_method"),
        "local_tls_verified": cfg.get("local_tls_verified"),
    }
    if cfg.get("certificate_path"):
        try:
            p = _run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(cfg["certificate_path"]),
                    "-noout",
                    "-enddate",
                ],
                check=False,
                timeout=5,
            )
            result["certificate_not_after"] = p.stdout.strip().removeprefix("notAfter=")
        except Exception:
            pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser(prog="web_publish.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    conf = sub.add_parser("configure")
    conf.add_argument("--domain", required=True)
    cert_group = conf.add_mutually_exclusive_group(required=True)
    cert_group.add_argument("--auto-cert", action="store_true")
    cert_group.add_argument("--existing-cert", action="store_true")
    conf.add_argument("--cert")
    conf.add_argument("--key")

    sub.add_parser("refresh")
    sub.add_parser("remove")
    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "configure":
        result = configure(
            args.domain,
            auto_cert=bool(args.auto_cert),
            cert_path=args.cert,
            key_path=args.key,
        )
    elif args.cmd == "refresh":
        result = refresh()
    elif args.cmd == "remove":
        result = remove()
    else:
        result = status()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
