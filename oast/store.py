#!/usr/bin/env python3
"""
Interaction Store
=================
Thread-safe in-memory store of OAST interactions.

Each interaction is keyed by a correlation token. Tokens have a TTL.
Supports:
  - register_token(token)
  - add(token, interaction)
  - get(token) -> [interactions]
  - has(token) -> bool
  - clear(token)
  - stats()
  - Auto-cleanup of expired tokens
"""
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Optional


class InteractionStore:
    """
    In-memory store for OAST interactions.

    Interactions are stored per token. A background thread periodically
    removes expired tokens and their interactions.
    """

    def __init__(self, ttl_seconds: int = 3600, max_per_token: int = 200):
        """
        Args:
            ttl_seconds: How long to keep each token's data
            max_per_token: Max interactions to keep per token
        """
        self.lock = threading.RLock()
        self.interactions: Dict[str, List[Dict]] = defaultdict(list)
        self.tokens: Dict[str, float] = {}
        self.ttl = ttl_seconds
        self.max_per_token = max_per_token
        self.total_count = 0
        self._cleanup_thread = None
        self._stop_event = threading.Event()
        self._start_cleanup()

    # ═══════════════════════════════════════════════════════════════════════
    #  Token management
    # ═══════════════════════════════════════════════════════════════════════

    def register_token(self, token: str) -> None:
        """Register a new token (or refresh existing)."""
        with self.lock:
            self.tokens[token] = time.time()

    def has_token(self, token: str) -> bool:
        with self.lock:
            return token in self.tokens

    # ═══════════════════════════════════════════════════════════════════════
    #  Interactions
    # ═══════════════════════════════════════════════════════════════════════

    def add(self, token: str, interaction: Dict) -> None:
        """Record an interaction for a token."""
        with self.lock:
            # Auto-register token if new
            if token not in self.tokens:
                self.tokens[token] = time.time()

            lst = self.interactions[token]
            lst.append(interaction)

            # Cap per-token
            if len(lst) > self.max_per_token:
                self.interactions[token] = lst[-self.max_per_token:]

            self.total_count += 1

    def get(self, token: str) -> List[Dict]:
        """Get all interactions for a token."""
        with self.lock:
            return list(self.interactions.get(token, []))

    def has(self, token: str) -> bool:
        """Check if a token has any interactions."""
        with self.lock:
            return bool(self.interactions.get(token))

    def clear(self, token: str) -> None:
        """Delete a token and its interactions."""
        with self.lock:
            self.interactions.pop(token, None)
            self.tokens.pop(token, None)

    def clear_all(self) -> None:
        """Delete everything."""
        with self.lock:
            self.interactions.clear()
            self.tokens.clear()
            self.total_count = 0

    # ═══════════════════════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════════════════════

    def stats(self) -> Dict:
        with self.lock:
            tokens_with_hits = sum(
                1 for t in self.interactions if self.interactions[t]
            )
            return {
                "total_interactions": self.total_count,
                "active_tokens": len(self.tokens),
                "tokens_with_hits": tokens_with_hits,
                "stored_interactions": sum(
                    len(v) for v in self.interactions.values()
                ),
            }

    # ═══════════════════════════════════════════════════════════════════════
    #  Auto cleanup
    # ═══════════════════════════════════════════════════════════════════════

    def cleanup_expired(self) -> int:
        """
        Remove expired tokens and interactions.
        Returns number of tokens removed.
        """
        cutoff = time.time() - self.ttl
        removed = 0
        with self.lock:
            # Remove old interactions per token
            for token in list(self.interactions.keys()):
                self.interactions[token] = [
                    i for i in self.interactions[token]
                    if i.get("timestamp", 0) > cutoff
                ]
                if not self.interactions[token]:
                    del self.interactions[token]

            # Remove old tokens
            for token in list(self.tokens.keys()):
                if self.tokens[token] < cutoff:
                    del self.tokens[token]
                    removed += 1
        return removed

    def _start_cleanup(self):
        """Start background cleanup thread."""
        def loop():
            while not self._stop_event.wait(300):  # every 5 min
                try:
                    self.cleanup_expired()
                except Exception:
                    pass

        self._cleanup_thread = threading.Thread(target=loop, daemon=True)
        self._cleanup_thread.start()

    def stop(self):
        """Stop cleanup thread."""
        self._stop_event.set()
        if self._cleanup_thread:
            try:
                self._cleanup_thread.join(timeout=2)
            except Exception:
                pass