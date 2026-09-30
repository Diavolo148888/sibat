"""Module: secret_verify — READ-ONLY live checks for candidate secrets.

Found an AWS key or GitHub token in client code or an exposed file?
This module performs the minimal, non-invasive validity check — the step
that separates a report from a false positive. It never uses a secret
beyond confirming whether it authenticates: no listing, no reading,
no modification. Using a found credential for anything beyond a
validity check is a crime.

Checks:
  - AWS access key (AKIA...): STS GetCallerIdentity via SigV4 —
    implemented with hashlib/hmac (stdlib), read-only.
  - GitHub token (ghp_/gho_/ghu_/ghs_/ghr_): GET /user with the token —
    read-only metadata endpoint.
  - Generic bearer-shaped JWT: decode-only (claims inspection, no
    network call, never accepted as a secret by itself).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import urllib.error
import urllib.request

from ..core.models import Finding
from ..core.scope import ScopeGuard

UA = "SIBAT/secret-verify (read-only validity check)"


# ------------------------------------------------------------------ AWS

def _sigv4_headers(access_key: str, secret_key: str, host: str, service: str,
                   region: str = "us-east-1") -> dict:
    """Minimal SigV4 for a one-shot GET (stdlib only)."""
    t = _dt.datetime.now(_dt.timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    canonical_uri = "/"
    canonical_query = ""
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        "GET", canonical_uri, canonical_query, canonical_headers,
        signed_headers, payload_hash,
    ])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k_date = _h(("AWS4" + secret_key).encode(), datestamp)
    k_region = _h(k_date, region)
    k_service = _h(k_region, service)
    k_signing = _h(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders={signed_headers}, Signature={signature}"),
        "x-amz-date": amz_date,
    }


def _verify_aws(access_key: str, secret_key: str) -> Finding:
    """STS GetCallerIdentity — read-only. NOTE: the secret key is normally
    NOT present in client-side leaks (only the access key id is). Without
    it, validity cannot be confirmed; we report the candidate as-is."""
    if not secret_key:
        return Finding(
            category="secret_verify", host="aws", severity="info",
            title="AWS key candidate — no secret key available",
            detail=("only the access key id is present, so validity cannot be "
                    "confirmed programmatically. Report the exposure with the "
                    "key REDACTED; the program will rotate and confirm."),
        )
    headers = _sigv4_headers(access_key, secret_key, "sts.amazonaws.com", "sts")
    req = urllib.request.Request("https://sts.amazonaws.com/", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read(4096).decode("utf-8", "replace")
        if "GetCallerIdentityResponse" in body:
            return Finding(
                category="secret_verify", host="aws", severity="high",
                title="AWS credentials are LIVE (read-only check)",
                detail=("GetCallerIdentity succeeded — the pair authenticates. "
                        "REPORT IMMEDIATELY. Do not list, read, or modify "
                        "anything. Body snippet (account id only): " +
                        (body[body.find("<Account>"):body.find("</Account>") + 10] if "<Account>" in body else "n/a")),
            )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return Finding(
                category="secret_verify", host="aws", severity="low",
                title="AWS credentials are dead (403 from STS)",
                detail="the pair does not authenticate — not reportable as a live key",
            )
        return Finding(
            category="secret_verify", host="aws", severity="info",
            title=f"AWS check inconclusive (HTTP {e.code})", detail="retry later",
        )
    except OSError:
        return Finding(
            category="secret_verify", host="aws", severity="info",
            title="AWS check inconclusive (network)", detail="retry later",
        )
    return Finding(category="secret_verify", host="aws", severity="info",
                   title="AWS check inconclusive", detail="unexpected response")


# ------------------------------------------------------------------ GitHub

def _verify_github(token: str) -> Finding:
    req = urllib.request.Request("https://api.github.com/user",
                                 headers={"Authorization": f"Bearer {token}",
                                          "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        login = data.get("login", "?")
        return Finding(
            category="secret_verify", host="github", severity="high",
            title=f"GitHub token is LIVE (account: {login})",
            detail=("GET /user succeeded — the token authenticates. "
                    "REPORT IMMEDIATELY. Do not read repos, list orgs, or "
                    "take any action with it."),
        )
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return Finding(
                category="secret_verify", host="github", severity="low",
                title="GitHub token is dead (401)",
                detail="token does not authenticate — not reportable as live",
            )
        if e.code == 403:
            return Finding(
                category="secret_verify", host="github", severity="info",
                title="GitHub token rate-limited or restricted",
                detail="retry later; check token scopes",
            )
        return Finding(
            category="secret_verify", host="github", severity="info",
            title=f"GitHub check inconclusive (HTTP {e.code})", detail="retry later",
        )
    except (OSError, json.JSONDecodeError):
        return Finding(
            category="secret_verify", host="github", severity="info",
            title="GitHub check inconclusive (network)", detail="retry later",
        )


# ------------------------------------------------------------------ dispatcher

MODULE = {
    "name": "secret_verify",
    "title": "Secret live-verification (READ-ONLY)",
    "desc": "Read-only validity checks for candidate secrets: AWS STS, GitHub /user. Never uses a secret beyond confirming it authenticates.",
    "risk": "low",
    "targeted": False,
}


def run(guard: ScopeGuard, target: str, port: int | None = None,
        aws_key: str | None = None, aws_secret: str | None = None,
        github_token: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    if aws_key:
        out.append(_verify_aws(aws_key, aws_secret or ""))
    if github_token:
        out.append(_verify_github(github_token))
    if not out:
        out.append(Finding(
            category="secret_verify", host=target, severity="info",
            title="Nothing to verify",
            detail="pass a candidate: --aws-key AKIA... [--aws-secret ...] or --github-token ghp_...",
        ))
    return out
