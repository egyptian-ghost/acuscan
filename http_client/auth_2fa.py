#!/usr/bin/env python3
"""2FA/TOTP authentication support."""
import re
import time
import base64
import struct
import hashlib
import hmac

try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

from urllib.parse import quote


class TwoFactorAuth:
    """TOTP/2FA helper."""

    def __init__(self, config):
        self.config = config
        self.secret = config.get("totp_secret")
        self.digits = config.get("totp_digits", 6)
        self.interval = config.get("totp_interval", 30)
        self.algorithm = config.get("totp_algorithm", "SHA1")
        self.backup_codes = config.get("totp_backup_codes", [])
        self.manual_code = config.get("totp_code")
        self._used_backup = set()
        self._time_drift = config.get("_totp_drift", 0)

    def _digest(self):
        return {
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }.get(self.algorithm.upper(), hashlib.sha1)

    def _manual_totp(self, at_time=None):
        try:
            secret_padded = self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8)
            secret_bytes = base64.b32decode(secret_padded)
            counter = int(((at_time or time.time()) + self._time_drift) // self.interval)
            msg = struct.pack(">Q", counter)
            digest = self._digest()
            hmac_hash = hmac.new(secret_bytes, msg, digest).digest()
            offset = hmac_hash[-1] & 0x0F
            code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0]
            code &= 0x7FFFFFFF
            code %= 10 ** self.digits
            return str(code).zfill(self.digits)
        except Exception:
            return None

    def generate_code(self, at_time=None):
        if self.manual_code:
            return self.manual_code
        if not self.secret:
            return None
        if HAS_PYOTP:
            try:
                totp = pyotp.TOTP(
                    self.secret, digits=self.digits,
                    interval=self.interval, digest=self._digest()
                )
                if at_time is not None:
                    return totp.at(at_time + self._time_drift)
                return totp.now()
            except Exception:
                pass
        return self._manual_totp(at_time)

    def generate_hotp(self, counter):
        if not self.secret:
            return None
        try:
            secret_padded = self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8)
            secret_bytes = base64.b32decode(secret_padded)
            msg = struct.pack(">Q", counter)
            hmac_hash = hmac.new(secret_bytes, msg, self._digest()).digest()
            offset = hmac_hash[-1] & 0x0F
            code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0]
            code &= 0x7FFFFFFF
            code %= 10 ** self.digits
            return str(code).zfill(self.digits)
        except Exception:
            return None

    def get_backup_code(self):
        for code in self.backup_codes:
            if code not in self._used_backup:
                self._used_backup.add(code)
                return code
        return None

    def verify_code(self, code, window=1):
        if not code:
            return False
        now = int(time.time())
        for offset in range(-window, window + 1):
            expected = self.generate_code(now + offset * self.interval)
            if expected and expected == code:
                return True
        return code in self.backup_codes

    def generate_qr(self, account_name="user", issuer="AcuScan", output_path=None):
        if not self.secret:
            return None
        uri = (
            f"otpauth://totp/{quote(issuer)}:{quote(account_name)}"
            f"?secret={self.secret}&issuer={quote(issuer)}"
            f"&digits={self.digits}&period={self.interval}"
            f"&algorithm={self.algorithm}"
        )
        if HAS_QRCODE and output_path:
            try:
                img = qrcode.make(uri)
                img.save(output_path)
                return output_path
            except Exception:
                pass
        return uri

    def sync_with_server(self, server_url, http_client):
        try:
            resp = http_client.head(server_url, timeout=5)
            if not resp:
                return False
            server_date = resp.headers.get("Date", "")
            if not server_date:
                return False
            from email.utils import parsedate_to_datetime
            server_time = parsedate_to_datetime(server_date).timestamp()
            local_time = time.time()
            drift = server_time - local_time
            if abs(drift) > 5:
                self._time_drift = drift
                self.config["_totp_drift"] = drift
                return True
        except Exception:
            pass
        return False