"""Thin Kusto client that works against the emulator and a real ADX cluster.

The emulator has no authentication, so the stdlib path is enough for it and keeps
`make up/ingest/test` dependency-free. For a real cluster we defer to
azure-kusto-data, which handles AAD. Detections and tests never know which is in use.
"""
from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from typing import Any

from . import config


class KustoError(RuntimeError):
    """A query or management command was rejected by the engine."""


class KustoResult:
    """Column names plus rows, with light helpers used by the test harness."""

    def __init__(self, columns: list[str], rows: list[list[Any]]):
        self.columns = columns
        self.rows = rows

    def __len__(self) -> int:
        return len(self.rows)

    @property
    def empty(self) -> bool:
        return not self.rows

    def dicts(self) -> list[dict[str, Any]]:
        # strict=True: a row whose width differs from the column list means the
        # response was malformed, and silently truncating it would hide that.
        return [dict(zip(self.columns, row, strict=True)) for row in self.rows]

    def column(self, name: str) -> list[Any]:
        if name not in self.columns:
            raise KeyError(f"column {name!r} not in result: {self.columns}")
        i = self.columns.index(name)
        return [row[i] for row in self.rows]

    def scalar(self) -> Any:
        if not self.rows or not self.rows[0]:
            raise KustoError("expected a scalar, got an empty result")
        return self.rows[0][0]


class KustoClient:
    def __init__(self, uri: str | None = None, database: str | None = None):
        self.uri = (uri or config.kusto_uri()).rstrip("/")
        self.database = database or config.kusto_db()
        self._mode = config.auth_mode()
        self._sdk = None
        if self._mode != "none":
            self._sdk = self._build_sdk_client()

    # ---------------- transport ----------------

    def _build_sdk_client(self):
        try:
            from azure.kusto.data import KustoClient as _C
            from azure.kusto.data import KustoConnectionStringBuilder as _B
        except ImportError as exc:  # pragma: no cover
            raise KustoError(
                "KUSTO_AUTH_MODE is not 'none' but azure-kusto-data is not installed. "
                "Run: pip install -r requirements.txt"
            ) from exc
        if self._mode == "device":
            builder = _B.with_interactive_login(self.uri)
        elif self._mode == "azure_cli":
            builder = _B.with_az_cli_authentication(self.uri)
        else:
            raise KustoError(
                f"unknown KUSTO_AUTH_MODE={self._mode!r}; "
                "use 'none' (emulator), 'device' or 'azure_cli'"
            )
        return _C(builder)

    def _post_stdlib(self, endpoint: str, csl: str) -> KustoResult:
        payload = json.dumps({"db": self.database, "csl": csl}).encode()
        request = urllib.request.Request(
            f"{self.uri}/v1/rest/{endpoint}",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        # The emulator is local; never route it through an HTTP proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=600) as response:
                body = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", "replace").strip()
            message = f"HTTP {exc.code}"
            try:
                parsed = json.loads(body_text)
                error = parsed.get("error", parsed)
                message = (
                    error.get("@message")
                    or error.get("message")
                    or error.get("Message")
                    or message
                )
                inner = error.get("@innererror") or {}
                detail = inner.get("@message") or inner.get("message")
                if detail and detail != message:
                    message = f"{message}: {detail}"
            except (json.JSONDecodeError, AttributeError):
                first = next((ln for ln in body_text.splitlines() if ln.strip()), "")
                message = first or message
            raise KustoError(
                f"{message}\n  while running: {csl.strip()[:300]}"
            ) from None
        except urllib.error.URLError as exc:
            raise KustoError(
                f"cannot reach Kusto at {self.uri} ({exc.reason}). "
                "Is the emulator running? Try: python tasks.py up"
            ) from None
        except (TimeoutError, ConnectionError, http.client.HTTPException, OSError) as exc:
            # The engine resets connections while it is still starting up.
            raise KustoError(
                f"transport error talking to Kusto at {self.uri}: {exc}"
            ) from None
        except json.JSONDecodeError as exc:
            raise KustoError(f"Kusto returned a non-JSON response: {exc}") from None
        table = body["Tables"][0]
        return KustoResult([c["ColumnName"] for c in table["Columns"]], table["Rows"])

    def _post_sdk(self, endpoint: str, csl: str) -> KustoResult:
        try:
            if endpoint == "mgmt":
                response = self._sdk.execute_mgmt(self.database, csl)
            else:
                response = self._sdk.execute_query(self.database, csl)
        except Exception as exc:
            raise KustoError(f"{exc}\n  while running: {csl.strip()[:200]}") from None
        table = response.primary_results[0]
        columns = [c.column_name for c in table.columns]
        return KustoResult(columns, [list(r) for r in table])

    # ---------------- public API ----------------

    def query(self, csl: str) -> KustoResult:
        if self._sdk is not None:
            return self._post_sdk("query", csl)
        return self._post_stdlib("query", csl)

    def mgmt(self, csl: str) -> KustoResult:
        if self._sdk is not None:
            return self._post_sdk("mgmt", csl)
        return self._post_stdlib("mgmt", csl)

    def is_reachable(self) -> bool:
        try:
            self.mgmt(".show version")
            return True
        except KustoError:
            return False

    def engine_version(self) -> str:
        return str(self.mgmt(".show version").rows[0][0])

    def table_exists(self, name: str) -> bool:
        try:
            result = self.mgmt(".show tables")
        except KustoError:
            return False
        return name in [row[0] for row in result.rows]

    def row_count(self, table: str = config.RAW_TABLE) -> int:
        return int(self.query(f"{table} | count").scalar())
