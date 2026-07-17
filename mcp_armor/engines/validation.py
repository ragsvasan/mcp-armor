"""T3 — Input Validation: JSON schema strict mode, injection guards, size limits."""

from __future__ import annotations

import logging
import threading

from ..context import CoSAIContext
from ..exceptions import ValidationError
from ..types import (
    CONTENT_BEARING_METHODS,
    MCPRequest,
    MCPResponse,
    scannable_strings,
)

log = logging.getLogger(__name__)

_MAX_PAYLOAD_BYTES = 65_536

# T3-002: shell command injection
_CMD_PATTERNS: tuple[str, ...] = (
    r"[;&|`]",
    r"\$\(",
    r"\$\{",  # ${VAR} and ${IFS} expansions
    r"[<>]",  # shell redirects
    r"(?i)\bexec\s*\(",
    r"(?i)\beval\s*\(",
    r"(?i)\bsystem\s*\(",
    r"(?i)\bpopen\s*\(",
    r"(?i)\bcmd\s*/[cCkK]\b",  # Windows cmd /c
    r"(?i)%[A-Za-z_][A-Za-z_0-9]*%",  # Windows %ENVVAR%
)

# T3-003: path traversal
_PATH_PATTERNS: tuple[str, ...] = (
    r"\.\.[/\\]",
    r"[/\\]\.\.",
    r"(?i)%2e%2e(?:[/\\]|%2f|%5c)",
    r"(?i)%252e%252e",
    r"(?i)/etc/",
    r"(?i)/proc/self",
    r"(?i)(?:/root|/home/[^/]+)/\.ssh/",
    r"(?i)[A-Za-z]:[/\\](?:Windows|System32|Users)",
    r"(?i)\\\\\.\\\\",
)

# T3-004: SQL injection
_SQL_PATTERNS: tuple[str, ...] = (
    r"(?i)'\s*(OR|AND)\s+['\"0-9]",
    r"(?i)\b(OR|AND)\s+\d+\s*=\s*\d+",  # numeric tautology: OR 1=1
    r"(?i);\s*(?:DROP|DELETE|TRUNCATE|INSERT|UPDATE|ALTER|CREATE)\s+",
    r"(?i)UNION\s+(?:ALL\s+)?SELECT",
    r"--",  # SQL comment (all forms)
    r"(?i)/\*.*?\*/",
    r"(?i)\bXP_\w+",
    r"(?i)WAITFOR\s+DELAY",
    r"(?i)SLEEP\s*\(",
)


def _compile(patterns: tuple[str, ...]) -> list:
    try:
        import re2 as re
    except ImportError:
        import re  # type: ignore[no-redef]
    return [re.compile(p) for p in patterns]


class ValidationEngine:
    """
    Validates all tool call inputs before dispatch.

    Covers:
    - T3-001: Oversized payload (denial of service via memory exhaustion)
    - T3-002: Command injection in string arguments (including nested containers)
    - T3-003: Path traversal (../ sequences)
    - T3-004: SQL injection patterns
    - T3-005: Unknown fields in strict-schema mode / required fields missing
    """

    def __init__(
        self,
        max_payload_bytes: int = _MAX_PAYLOAD_BYTES,
        strict_schema: bool = True,
    ) -> None:
        self._max_payload_bytes = max_payload_bytes
        self._strict_schema = strict_schema
        self._tool_schemas: dict[str, dict] = {}
        # Guards _tool_schemas — on_response auto-registration can run on multiple
        # concurrent asyncio tasks (one per session); the lock keeps registration
        # from interleaving partial writes.
        self._schema_lock = threading.Lock()
        self._cmd = _compile(_CMD_PATTERNS)
        self._path = _compile(_PATH_PATTERNS)
        self._sql = _compile(_SQL_PATTERNS)

    def register_tools(self, tools: list[dict]) -> None:
        """Populate tool input schemas from a tools/list result.

        First-write-wins per tool name: the FIRST observed manifest is the trusted
        baseline (the same baseline IntegrityEngine snapshots for T6 drift). A
        later or attacker-influenced tools/list cannot silently relax an already
        registered schema — that would let a drifted/poisoned manifest weaken
        strict-schema enforcement process-wide (the store is shared across
        sessions). Mid-session manifest *change* is the rug-pull IntegrityEngine
        (T6) detects; here we simply refuse to downgrade.
        """
        with self._schema_lock:
            for tool in tools:
                name = tool.get("name", "")
                if name and name not in self._tool_schemas:
                    self._tool_schemas[name] = tool.get("inputSchema") or {}

    def _scan_injection(self, value: str, field: str) -> None:
        for pat in self._cmd:
            if pat.search(value):
                raise ValidationError(
                    f"Command injection pattern in argument {field!r}: {pat.pattern!r}"
                )
        for pat in self._path:
            if pat.search(value):
                raise ValidationError(
                    f"Path traversal pattern in argument {field!r}: {pat.pattern!r}"
                )
        for pat in self._sql:
            if pat.search(value):
                raise ValidationError(
                    f"SQL injection pattern in argument {field!r}: {pat.pattern!r}"
                )

    def _scan_all_strings(self, value: object, field: str) -> None:
        """Recursively scan all string values inside dicts and lists."""
        if isinstance(value, str):
            self._scan_injection(value, field)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._scan_all_strings(item, f"{field}[{i}]")
        elif isinstance(value, dict):
            for k, v in value.items():
                self._scan_all_strings(v, f"{field}.{k}")

    def _validate_schema(self, arguments: object, schema: dict, tool_name: str) -> None:
        try:
            import jsonschema
        except ImportError as exc:
            # M2: never silently skip validation when strict_schema is on.
            # on_startup already fails closed for this case, so reaching here
            # means jsonschema became unimportable AFTER a successful startup —
            # still refuse to let the T3-005 schema gate degrade to a no-op.
            if self._strict_schema:
                from ..config import ConfigError

                raise ConfigError(
                    "strict_schema=True but the 'jsonschema' package is not "
                    "importable at validation time — refusing to skip T3-005 "
                    "schema enforcement."
                ) from exc
            return

        if self._strict_schema:
            schema = {**schema, "additionalProperties": False}

        try:
            jsonschema.Draft7Validator(schema).validate(arguments)
        except jsonschema.ValidationError as exc:
            raise ValidationError(
                f"Tool {tool_name!r} argument schema violation: {exc.message}"
            ) from exc

    async def on_startup(self) -> None:
        # M2: strict_schema enforcement (T3-005) depends on the optional
        # `jsonschema` package. If it is absent, `_validate_schema` would skip
        # ALL schema validation silently — a security downgrade the operator who
        # set strict_schema=True never consented to (malformed/extra arguments a
        # schema would reject would sail through every tools/call). Fail closed
        # at startup so the misconfiguration surfaces before the server accepts
        # any traffic, rather than degrading enforcement to a silent no-op.
        if self._strict_schema:
            try:
                import jsonschema  # noqa: F401
            except ImportError as exc:
                from ..config import ConfigError

                raise ConfigError(
                    "strict_schema=True requires the optional 'jsonschema' "
                    "package, but it is not importable. Install jsonschema or "
                    "construct the ValidationEngine with strict_schema=False. "
                    "Refusing to start with T3-005 schema validation silently "
                    "disabled."
                ) from exc

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # F2 fix: validate every content-bearing method (tools/call,
        # resources/read, resources/subscribe, prompts/get) — not just
        # tools/call. resources/read.uri = file:///etc/passwd was previously
        # unscanned for path traversal / injection.
        #
        # BLOCK[1] fix: the T3-001 size-limit and the tools/call strict-schema
        # / unknown-tool gate MUST run for ANY content-bearing method,
        # independent of whether `scannable_strings` extracted any fields. A
        # `tools/call` with empty/abnormal params (no name, no arguments, no
        # uri) yields `{}` here; gating these checks on a non-empty `fields`
        # let an attacker bypass the payload-size DoS guard and the schema
        # enforcement simply by omitting the standard param keys. The
        # field-extraction result only governs the per-field injection scans
        # below, never the size/schema gates.
        is_content_method = req.method in CONTENT_BEARING_METHODS
        fields = scannable_strings(req)
        if not is_content_method and not fields:
            return ctx

        # T3-001: size limit — runs for every content-bearing method even when
        # no scannable field was extracted (empty/abnormal params).
        raw = str(req.params)
        if len(raw.encode()) > self._max_payload_bytes:
            raise ValidationError(f"Payload exceeds {self._max_payload_bytes} bytes")

        arguments = req.params.get("arguments")
        tool_name = str(req.params.get("name", ""))

        # T3-002/003/004: reject non-dict, non-None arguments outright (cannot scan safely)
        if arguments is not None and not isinstance(arguments, dict):
            raise ValidationError(
                f"Tool {tool_name!r}: 'arguments' must be an object, got {type(arguments).__name__}"
            )

        # Recursively scan all string values including nested lists/dicts.
        # Covers arguments AND the resources/* `uri` field (F2).
        if arguments is not None:
            self._scan_all_strings(arguments, "arguments")
        uri = fields.get("uri")
        if uri is not None:
            if not isinstance(uri, str):
                raise ValidationError(
                    f"{req.method!r}: 'uri' must be a string, got {type(uri).__name__}"
                )
            self._scan_injection(uri, "uri")

        # T3-005: JSON schema validation — only applies to tool calls. Schemas
        # are auto-registered from the observed tools/list response (on_response).
        if self._strict_schema and req.method == "tools/call":
            if not self._tool_schemas:
                # No manifest has been observed on this engine instance yet. This
                # happens on paths that don't route tools/list through this guard
                # before tools/call: the per-call dispatcher adapter, the FastMCP
                # decorator (_GuardedToolDispatcher), a multi-worker deployment
                # where tools/list landed on another worker, or a client that
                # cached the manifest. Hard-rejecting here is exactly the A1
                # self-DoS (every tools/call → "no registered schema"). Skip the
                # SCHEMA gate only (the size + injection gates above already ran)
                # until a manifest is registered; never fail closed pre-manifest.
                log.warning(
                    "T3 strict_schema: no tools/list manifest observed yet — "
                    "schema validation skipped for tool %r (injection/size gates "
                    "still enforced). Route tools/list through this guard before "
                    "tools/call to enable schema enforcement.",
                    tool_name,
                )
            elif tool_name not in self._tool_schemas:
                # A manifest IS known and this tool is not in it — fail closed.
                raise ValidationError(
                    f"Tool {tool_name!r} is not in the observed tools/list "
                    "manifest — unknown tool rejected (T3-005)"
                )
            else:
                schema = self._tool_schemas[tool_name]
                if schema:
                    self._validate_schema(arguments or {}, schema, tool_name)

        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        # A1 fix: auto-register tool input schemas from the observed tools/list
        # response — mirroring IntegrityEngine.on_response / SupplyChainEngine.
        # on_response. Without this, `_tool_schemas` is never populated on any
        # live adapter path, so with the default strict_schema=True EVERY
        # tools/call was rejected with "no registered schema" (self-DoS).
        #
        # The MCP protocol mandates that a client fetches tools/list (to learn
        # tool names + inputSchema) before it can issue a tools/call, and the
        # adapter routes that tools/list response through this hook, so by the
        # time the first tools/call arrives the schema is registered. Schemas
        # live on the engine instance (shared across sessions by the guard), so
        # one observed manifest populates enforcement for all callers.
        if resp.result is not None and "tools" in resp.result:
            tools = resp.result.get("tools")
            if isinstance(tools, list):
                self.register_tools([t for t in tools if isinstance(t, dict)])
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
