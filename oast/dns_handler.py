#!/usr/bin/env python3
"""
OAST DNS Handler
================
Optional DNS server that records DNS queries as interactions.
Requires: pip install dnslib

If dnslib is not installed, HAS_DNSLIB = False and DNS is disabled.
"""

try:
    from dnslib import DNSRecord, RR, QTYPE, A
    from dnslib.server import DNSServer, BaseResolver
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    DNSRecord = None
    RR = None
    QTYPE = None
    A = None
    DNSServer = None
    BaseResolver = object  # fallback so class definition works


if HAS_DNSLIB:
    class OASTDNSResolver(BaseResolver):
        """
        DNS resolver that records queries and responds with a fixed IP.
        """

        def __init__(self, router, listen_ip: str = "0.0.0.0"):
            self.router = router
            self.listen_ip = listen_ip

        def resolve(self, request, handler):
            try:
                qname = str(request.q.qname).rstrip('.')
                try:
                    source_ip = handler.client_address[0]
                except Exception:
                    source_ip = "unknown"
                qtype = QTYPE.get(request.q.qtype, "UNKNOWN")

                # Extract token from qname
                token = self.router.extract_token(qname, "/")
                if token:
                    self.router.record(
                        token, source_ip,
                        f"DNS-{qtype}", qname,
                        {}, "",
                        protocol="dns", host=qname,
                    )

                # Build reply with our IP
                reply = request.reply()
                try:
                    reply.add_answer(RR(
                        qname, QTYPE.A,
                        rdata=A(self.listen_ip),
                        ttl=60,
                    ))
                except Exception:
                    pass
                return reply
            except Exception:
                return request.reply()

else:
    class OASTDNSResolver:
        """Placeholder when dnslib is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "dnslib is required for DNS OAST. "
                "Install with: pip install dnslib"
            )