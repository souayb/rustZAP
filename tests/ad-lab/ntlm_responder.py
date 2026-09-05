#!/usr/bin/env python3
"""Minimal WinRM-port NTLM responder for LAB validation of `rustzap ad`.

Speaks just enough of the HTTP NTLM handshake that a client's NTLMSSP type-1
elicits a real, correctly-encoded type-2 CHALLENGE in `WWW-Authenticate`. The
challenge advertises DELIBERATELY WEAK negotiate flags (no signing, no extended
session security) so the NTLMv1 / NTLM-signing detections fire. NOT WinRM — it
validates the client wire path + report correlation, not Windows behaviour.
"""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer

# NTLMSSP type-2 with weak flags: UNICODE(0x1) | NTLM(0x200); no SIGN(0x10),
# no SEAL(0x20), no EXTENDED_SESSIONSECURITY(0x80000).
FLAGS = 0x00000201


def type2_token() -> str:
    msg = (
        b"NTLMSSP\x00"
        + (2).to_bytes(4, "little")          # MessageType = 2
        + b"\x00" * 8                          # TargetNameFields
        + FLAGS.to_bytes(4, "little")          # NegotiateFlags (offset 20)
        + b"\x01\x23\x45\x67\x89\xab\xcd\xef"  # ServerChallenge
        + b"\x00" * 8                          # Reserved
    )
    return base64.b64encode(msg).decode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization", "")
        self.send_response(401)
        if auth.startswith("NTLM "):
            self.send_header("WWW-Authenticate", "NTLM " + type2_token())
        else:
            self.send_header("WWW-Authenticate", "NTLM")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *_a):  # silence
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 5985), Handler).serve_forever()
