"""Vulnerability verifiers registry."""
from .sqli import SQLiVerifier
from .xss import XSSVerifier
from .rce import RCEVerifier
from .lfi import LFIVerifier
from .ssrf import SSRFVerifier
from .ssti import SSTIVerifier
from .xxe import XXEVerifier
from .nosql import NoSQLVerifier


VERIFIERS = {
    "sqli": SQLiVerifier,
    "xss": XSSVerifier,
    "rce": RCEVerifier,
    "lfi": LFIVerifier,
    "ssrf": SSRFVerifier,
    "ssti": SSTIVerifier,
    "xxe": XXEVerifier,
    "nosql": NoSQLVerifier,
}

__all__ = list(VERIFIERS.keys()) + ["VERIFIERS"]