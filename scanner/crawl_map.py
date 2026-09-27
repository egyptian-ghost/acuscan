#!/usr/bin/env python3
"""
Crawl Map v6.5
==============
Records every URL, form, and parameter discovered during crawling.
Provides:
  - Flat list of all nodes
  - Hierarchical tree structure
  - Statistics (internal/external, content types, status codes)
"""
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse


@dataclass
class CrawlNode:
    """A single node in the crawl tree."""
    url: str
    status: int = 0
    content_type: str = ""
    content_length: int = 0
    method: str = "GET"
    depth: int = 0
    parent_url: str = ""
    title: str = ""
    forms: List[Dict] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    links_found: int = 0
    response_time_ms: float = 0.0
    is_external: bool = False
    error: str = ""

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "method": self.method,
            "depth": self.depth,
            "parent_url": self.parent_url,
            "title": self.title,
            "forms": self.forms,
            "parameters": self.parameters,
            "links_found": self.links_found,
            "response_time_ms": round(self.response_time_ms, 2),
            "is_external": self.is_external,
            "error": self.error,
        }


class CrawlMap:
    """Tracks the site structure discovered during crawling."""

    def __init__(self):
        self.nodes: Dict[str, CrawlNode] = {}
        self.lock = threading.RLock()
        self.base_url = ""
        self.base_domain = ""

    # ═══════════════════════════════════════════════════════════════════════
    #  Setup
    # ═══════════════════════════════════════════════════════════════════════

    def set_base(self, url: str):
        self.base_url = url
        parsed = urlparse(url)
        self.base_domain = parsed.netloc

    # ═══════════════════════════════════════════════════════════════════════
    #  Recording
    # ═══════════════════════════════════════════════════════════════════════

    def record(self, node: CrawlNode):
        """Record a node. Merges if the URL already exists."""
        with self.lock:
            # Detect external
            p = urlparse(node.url)
            node.is_external = (p.netloc != self.base_domain)

            if node.url in self.nodes:
                existing = self.nodes[node.url]
                # Merge parameters
                existing.parameters = list(
                    set(existing.parameters + node.parameters)
                )
                # Merge forms
                if node.forms:
                    existing_forms = {
                        json.dumps(f, sort_keys=True) for f in existing.forms
                    }
                    for f in node.forms:
                        f_str = json.dumps(f, sort_keys=True)
                        if f_str not in existing_forms:
                            existing.forms.append(f)
                            existing_forms.add(f_str)
                # Update fields if the new node has more info
                if node.status and not existing.status:
                    existing.status = node.status
                if node.title and not existing.title:
                    existing.title = node.title
                if node.content_length and not existing.content_length:
                    existing.content_length = node.content_length
                if node.response_time_ms and not existing.response_time_ms:
                    existing.response_time_ms = node.response_time_ms
                if node.error:
                    existing.error = node.error
                if node.links_found > existing.links_found:
                    existing.links_found = node.links_found
            else:
                self.nodes[node.url] = node

    # ═══════════════════════════════════════════════════════════════════════
    #  Retrieval
    # ═══════════════════════════════════════════════════════════════════════

    def get_all(self) -> List[Dict]:
        """Flat list of all nodes."""
        with self.lock:
            nodes = list(self.nodes.values())
            nodes.sort(key=lambda n: (n.depth, n.url))
            return [n.to_dict() for n in nodes]

    def get_tree(self) -> Dict:
        """
        Build hierarchical tree structure.

        Structure example:
        {
          "path": "/api",
          "_children": {
            "v1": {
              "path": "/api/v1",
              "_children": {
                "users": {
                  "path": "/api/v1/users",
                  "_node": {...full node data...}
                }
              }
            }
          }
        }
        """
        with self.lock:
            root = {"_children": {}}

            for url, node in self.nodes.items():
                parsed = urlparse(url)
                path = parsed.path or "/"
                # Skip URLs with query string for tree building
                # (they'll appear as parameters of their parent)
                parts = [p for p in path.split("/") if p]

                if not parts:
                    # Root node
                    root["_node"] = node.to_dict()
                    continue

                current = root["_children"]
                current_path = ""

                for i, part in enumerate(parts):
                    current_path += "/" + part

                    if part not in current:
                        current[part] = {
                            "path": current_path,
                            "_children": {},
                        }

                    if i == len(parts) - 1:
                        # Leaf node
                        current[part]["_node"] = node.to_dict()
                        # Also store query string params if any
                        if parsed.query:
                            qs = parse_qs(parsed.query)
                            current[part]["_query_params"] = list(qs.keys())

                    current = current[part]["_children"]

            return root

    def get_stats(self) -> Dict:
        """Compute statistics."""
        with self.lock:
            internal = [n for n in self.nodes.values() if not n.is_external]
            external = [n for n in self.nodes.values() if n.is_external]

            content_types = {}
            for n in internal:
                ct = (n.content_type or "unknown").split(";")[0].strip()
                content_types[ct] = content_types.get(ct, 0) + 1

            statuses = {}
            for n in internal:
                s = str(n.status or 0)
                statuses[s] = statuses.get(s, 0) + 1

            # Depth distribution
            depths = {}
            for n in internal:
                d = str(n.depth)
                depths[d] = depths.get(d, 0) + 1

            # Average response time
            times = [n.response_time_ms for n in internal
                    if n.response_time_ms > 0]
            avg_time = round(sum(times) / len(times), 2) if times else 0

            # Largest pages
            by_size = sorted(internal, key=lambda n: n.content_length,
                           reverse=True)[:10]

            return {
                "total": len(self.nodes),
                "internal": len(internal),
                "external": len(external),
                "with_forms": sum(1 for n in self.nodes.values() if n.forms),
                "with_params": sum(1 for n in self.nodes.values()
                                  if n.parameters),
                "content_types": content_types,
                "status_codes": statuses,
                "depths": depths,
                "avg_response_time_ms": avg_time,
                "largest_pages": [
                    {
                        "url": n.url,
                        "size": n.content_length,
                        "title": n.title,
                    }
                    for n in by_size
                ],
            }

    # ═══════════════════════════════════════════════════════════════════════
    #  Bulk access
    # ═══════════════════════════════════════════════════════════════════════

    def get_by_depth(self, depth: int) -> List[Dict]:
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if n.depth == depth
            ]

    def get_internal(self) -> List[Dict]:
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if not n.is_external
            ]

    def get_external(self) -> List[Dict]:
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if n.is_external
            ]

    def get_with_forms(self) -> List[Dict]:
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if n.forms
            ]

    def get_with_params(self) -> List[Dict]:
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if n.parameters
            ]


# Need this for get_tree
from urllib.parse import parse_qs