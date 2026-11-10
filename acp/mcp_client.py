"""Minimal stdio MCP client (stdlib only) for calling a third-party MCP server.

Speaks newline-delimited JSON-RPC 2.0 over the server's stdin/stdout:
initialize -> notifications/initialized -> tools/list -> tools/call.

It also measures, per result, whether the server itself returned any
provenance (source URL, version, timestamp, signer) as structured data, so the
logs can say honestly what a third-party tool did and did not attest.
"""
from __future__ import annotations

import json
import subprocess

PROTOCOL_VERSION = "2025-06-18"


class MCPError(Exception):
    pass


class StdioMCP:
    def __init__(self, argv: list[str], env: dict | None = None, timeout: float = 60.0):
        self.argv = list(argv)
        self.timeout = timeout
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, env=env, bufsize=1)
        self._id = 0
        init = self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                        "clientInfo": {"name": "acp", "version": "0.1.0"}})
        self.server_info = init.get("serverInfo", {})
        self.protocol_version = init.get("protocolVersion")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.tools = self._rpc("tools/list", {}).get("tools", [])

    def _send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise MCPError(f"server closed during {method}")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != self._id:
                continue  # notifications / logs
            if "error" in msg:
                raise MCPError(str(msg["error"]))
            return msg.get("result", {})

    def call(self, name: str, arguments: dict) -> dict:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def result_text(result: dict) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def provenance_fields(result: dict, url: str) -> dict:
    """What the tool result ITSELF carries as structured metadata (not what the
    harness adds). The URL echoed inside the text body is reported separately:
    it is in-band prose, not an attestation."""
    meta = dict(result.get("_meta") or {})
    sc = result.get("structuredContent") or {}
    ann = {}
    for c in result.get("content", []):
        ann.update(c.get("annotations") or {})
        ann.update(c.get("_meta") or {})
    structured = {**meta, **(sc if isinstance(sc, dict) else {}), **ann}
    keys = {k.lower() for k in structured}

    def has(*names):
        return any(any(n in k for n in names) for k in keys)

    return {
        "source_url": has("url", "uri", "source"),
        "version": has("version", "etag", "revision"),
        "timestamp": has("time", "date", "lastmodified", "retrieved"),
        "signer": has("sign", "signature", "jws"),
        "source_url_in_text_only": (not has("url", "uri", "source")) and url in result_text(result),
        "result_keys": sorted(result.keys()),
        "content_annotation_keys": sorted(ann.keys()),
    }
