"""Bounded tools and inert installation plans, with no shell execution."""
import http.client
import ipaddress
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlsplit


def update_plan(target: str) -> dict:
    if not isinstance(target, str) or not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-(?:a|b|rc)[0-9]{1,3})?", target):
        raise ValueError("Target must be a release version, for example 1.2.3")
    return {"package": "example-local-tool", "version": target, "mode": "recorded-plan",
            "command_arguments": ["python", "-m", "pip", "install", f"example-local-tool=={target}"],
            "executed": False}


def read_workspace(workspace: Path, relative: str, max_bytes: int = 65536) -> str:
    base = workspace.resolve()
    candidate = (base / relative).resolve()
    if candidate == base or not candidate.is_relative_to(base):
        raise ValueError("File must remain inside the example workspace")
    if not candidate.is_file() or candidate.stat().st_size > max_bytes:
        raise ValueError("File unavailable or exceeds byte budget")
    with candidate.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("File exceeds byte budget")
    return data.decode("utf-8")


def fetch_public_text(url: str, max_bytes: int = 65536) -> str:
    """Resolve once and connect to that IP while retaining original TLS identity."""
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("URL exceeds budget")
    parts = urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.port not in {None, 443}):
        raise ValueError("Only public HTTPS URLs on port 443 are supported")
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Every resolved address must be public")
    pinned_ip = addresses[0]
    deadline = time.monotonic() + 5
    connection = http.client.HTTPSConnection(parts.hostname, 443, timeout=5,
                                             context=ssl.create_default_context())
    # HTTPSConnection wraps this connected socket with the original hostname as SNI.
    # Passing the already-vetted numeric address prevents a second DNS lookup.
    connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
        (pinned_ip, 443), timeout=timeout, source_address=source_address)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        connection.request("GET", path, headers={"Host": parts.hostname, "Accept-Encoding": "identity"})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError("Remote response must be successful; redirects are not followed")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Compressed responses are not accepted")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > max_bytes):
            raise ValueError("Remote response exceeds byte budget")
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Remote response exceeds time budget")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(8192, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ValueError("Remote response exceeds byte budget")
        return data.decode("utf-8")
    finally:
        connection.close()


def summarize(text: str) -> dict:
    compact = " ".join(text.split())
    return {"summary": compact[:600], "method": "bounded text excerpt; no model call",
            "truncated": len(compact) > 600}
